# Unicorn bug: stale TLB_MMIO entry after uc_mem_map() in UC_HOOK_MEM_READ_UNMAPPED

**Upstream repo**: https://github.com/unicorn-engine/unicorn  
**Affected file**: `qemu/accel/tcg/cputlb.c`, function `load_helper`  
**Tested against**: Unicorn commit `7182636a687e5e005e3336108a653de3aec0362b`  
**Impact**: CPU silently reads 0 instead of the mapped value for any unmapped-read handler that calls `uc_mem_map()` — the exact pattern prescribed by the API documentation.

---

## What the documentation promises

`unicorn.h` lines 448–451 (the doc-comment for `uc_cb_eventmem_t`):

```
In the event of a UC_MEM_READ_UNMAPPED or UC_MEM_WRITE_UNMAPPED
callback, the memory should be uc_mem_map()-ed with the correct
permissions, and the instruction will then read or write to the
address as it was supposed to.
```

`samples/sample_x86.c` demonstrates the same pattern for writes
(registers `UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED`,
maps memory in the handler, returns `true`).

## What actually happens

The CPU reads 0.  No error is signalled.

---

## Root cause

`load_helper` in `cputlb.c` caches the TLB entry state in local variables
(`tlb_addr`, `index`, `entry`) *before* the unmapped-read hook fires.

```
Step 1 — TLB miss for unmapped page P
  tlb_fill() → unicorn_fill_tlb() → tlb_set_page()
  The page is unassigned in Unicorn's address space, so
  tlb_set_page_with_attrs() finds io_mem_unassigned:
    is_ram  = false
    addend  = 0
    address |= TLB_MMIO            ← TLB entry flagged as MMIO
  load_helper caches:
    tlb_addr = entry->addr_read & ~TLB_INVALID_MASK
             = 0xfffffffffffff000 | TLB_MMIO   (e.g. ...f200)

Step 2 — mr = memory_mapping(uc, paddr) → NULL (page not yet mapped)
  UC_HOOK_MEM_READ_UNMAPPED fires.
  Handler calls uc_mem_map(uc, page, 0x1000, UC_PROT_ALL).
    memory_map() → memory_region_add_subregion() → tlb_flush(cpu)
    TLB is completely cleared (all entries memset to -1).
  Handler returns true.

Step 3 — Handled path in load_helper
  if (!tlb_hit(env->uc, tlb_addr, addr))   ← checks CACHED tlb_addr
  tlb_hit computes:
    (0xfffffffffffff200 & PAGE_MASK) == (addr & PAGE_MASK)
    → 0xfffffffffffff000 == 0xfffffffffffff000  → TRUE
  Because tlb_hit only compares page-aligned bits, the stale MMIO
  entry still "matches". tlb_fill() is NOT called again. The TLB
  entry remains in the flushed (all-0xFF / MMIO) state.

Step 4 — Memory read
  if (tlb_addr & ~TARGET_PAGE_MASK)  → non-zero (TLB_MMIO bit set)
  → MMIO path taken: io_readx(env, iotlbentry, ...)
  iotlbentry was zeroed by tlb_flush → maps to io_mem_unassigned
  → returns 0
  CPU register gets 0 instead of the mapped value.
```

The `tlb_hit()` check is designed to detect a TLB miss for a *different*
page (e.g. a large-page miss).  It is not designed to detect that the TLB
was flushed and the existing entry is now garbage — and for the sentinel
address 0xffffffffffffffff the page-aligned bits of the stale entry
happen to equal the page-aligned bits of `addr`, so the check always
passes.

---

## Minimal reproducer

```c
#include <unicorn/unicorn.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// mov al, [0xffffffffffffffff]   (3 bytes: 67 A0 FF ...)
// hlt
static uint8_t CODE[] = { 0x67, 0xA0, 0xFF, 0xFF, 0xFF, 0xFF, 0xF4 };
#define CODE_BASE 0x1000
#define STACK_BASE 0x7fff0000
#define SENTINEL_PAGE 0xfffffffffffff000ULL

static bool on_unmapped(uc_engine *uc, uc_mem_type type,
                        uint64_t addr, int size, int64_t val, void *ud) {
    uint8_t page[4096];
    memset(page, 0xAB, sizeof(page));             // fill with 0xAB
    uint64_t pg = addr & ~0xFFFULL;
    uc_mem_map(uc, pg, 0x1000, UC_PROT_ALL);
    uc_mem_write(uc, pg, page, 0x1000);
    return true;
}

int main(void) {
    uc_engine *uc;
    uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    uc_ctl_set_tlb_mode(uc, UC_TLB_VIRTUAL);

    uc_mem_map(uc, CODE_BASE, 0x1000, UC_PROT_ALL);
    uc_mem_write(uc, CODE_BASE, CODE, sizeof(CODE));
    uc_mem_map(uc, STACK_BASE, 0x10000, UC_PROT_ALL);

    uint64_t rsp = STACK_BASE + 0x8000;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

    uc_hook hh;
    uc_hook_add(uc, &hh, UC_HOOK_MEM_READ_UNMAPPED,
                on_unmapped, NULL, 1, 0);

    uc_emu_start(uc, CODE_BASE, CODE_BASE + sizeof(CODE) - 1, 0, 0);

    uint64_t rax = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);

    printf("AL = 0x%02llx  (expected 0xAB)\n", rax & 0xFF);
    // Prints: AL = 0x00  (expected 0xAB)

    uc_close(uc);
}
```

---

## Fix

Inside the `if (handled)` block in `load_helper`, after the unmapped-read
hook returns `true`, force a fresh TLB lookup before checking `tlb_hit`.
`uc_mem_map()` calls `tlb_flush()` which clears the table and may resize
it; `index`, `entry`, and `tlb_addr` must all be recomputed.

```c
if (handled) {
    uc->invalid_error = UC_ERR_OK;
    /* The invalid handler commonly calls uc_mem_map(), which calls
     * tlb_flush() and may resize the TLB table.  Our cached tlb_addr,
     * index, and entry are stale.  Force a fresh lookup so that the
     * newly-mapped RAM region gets a correct (non-MMIO) TLB entry. */
    index = tlb_index(env, mmu_idx, addr);
    entry = tlb_entry(env, mmu_idx, addr);
    tlb_addr = -1;   /* tlb_hit(-1, …) → false immediately */
    if (!tlb_hit(env->uc, tlb_addr, addr)) {
        if (!victim_tlb_hit(env, mmu_idx, index, tlb_off,
                            addr & TARGET_PAGE_MASK)) {
            tlb_fill(env_cpu(env), addr, size,
                     access_type, mmu_idx, retaddr);
            index = tlb_index(env, mmu_idx, addr);
            entry = tlb_entry(env, mmu_idx, addr);
        }
        tlb_addr = code_read ? entry->addr_code : entry->addr_read;
        tlb_addr &= ~TLB_INVALID_MASK;
    }
    paddr = entry->paddr | (addr & ~TARGET_PAGE_MASK);
    ...
```

---

## User-space workaround (no Unicorn patch required)

Use `UC_HOOK_TLB_FILL` instead of `UC_HOOK_MEM_READ_UNMAPPED`.

`UC_HOOK_TLB_FILL` fires *inside* `unicorn_fill_tlb`, **before**
`tlb_set_page` runs.  Calling `uc_mem_map()` from within it is safe:
when `unicorn_fill_tlb` subsequently calls `tlb_set_page`, the region is
already registered in the address space, so `address_space_translate_for_iotlb`
finds the RAM mapping (`is_ram = true`), produces a non-MMIO TLB entry,
and `load_helper` takes the normal fast-path read.

```c
static bool tlb_fill_hook(uc_engine *uc, uint64_t address,
                          uc_mem_type type, uc_tlb_entry *result,
                          void *user_data) {
    uint8_t page[4096];
    populate_page(page, address);              // fill with your data
    uc_err err = uc_mem_map(uc, address, 0x1000, UC_PROT_ALL);
    if (err == UC_ERR_OK)
        uc_mem_write(uc, address, page, 0x1000);
    // UC_ERR_MAP = already mapped; leave contents as-is.

    result->paddr = address;                   // identity mapping
    result->perms = UC_PROT_ALL;
    return true;
}

// Registration (requires UC_TLB_VIRTUAL mode):
uc_ctl_set_tlb_mode(uc, UC_TLB_VIRTUAL);
uc_hook_add(uc, &hh, UC_HOOK_TLB_FILL, tlb_fill_hook, ctx, 1, 0);
```

The key ordering guarantee:

```
TLB miss
  → tlb_fill()
    → unicorn_fill_tlb()
      → UC_HOOK_TLB_FILL callback  ← uc_mem_map() here, RAM region registered
      → tlb_set_page()             ← sees RAM region, no TLB_MMIO
  → load_helper gets non-MMIO tlb_addr
  → normal RAM read path
```

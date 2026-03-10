# Unicorn bug: stale TLB entry after uc_mem_map() in UC_HOOK_MEM_READ_UNMAPPED (Fixed in 2.1.4)

**Upstream repo**: https://github.com/unicorn-engine/unicorn  
**Affected file**: `qemu/accel/tcg/cputlb.c`, function `load_helper`  
**Confirmed on**: Unicorn 2.1.1 (tag `867770c7`)  
**Impact**: CPU silently reads 0 instead of the mapped value when a
`UC_HOOK_MEM_READ_UNMAPPED` handler calls `uc_mem_map()` — the exact
pattern prescribed by the API documentation — for accesses whose
page-aligned address equals `0xFFFFFFFFFFFFF000` (see [Address sensitivity]).

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
  The page is unassigned; address_space_translate_for_iotlb()
  finds no RAM backing and returns prot = 0  (qemu/exec.c:548-550).
  tlb_set_page_with_attrs() sees prot=0, skips iotlb population,
  and stores addr_read = -1  (all-1s / TLB_INVALID).
  load_helper caches:
    tlb_addr = entry->addr_read & ~TLB_INVALID_MASK
             = 0xFFFFFFFFFFFFFFFF & ~0x800
             = 0xFFFFFFFFFFFFF7FF

Step 2 — mr = memory_mapping(uc, paddr) → NULL (page not yet mapped)
  UC_HOOK_MEM_READ_UNMAPPED fires.
  Handler calls uc_mem_map(uc, page, 0x1000, UC_PROT_ALL).
    memory_map() → memory_region_add_subregion() → tlb_flush(cpu)
    tlb_flush() memsets the CPUTLBEntry table and the iotlb array to -1.
  Handler returns true.

Step 3 — Handled path in load_helper
  if (!tlb_hit(env->uc, tlb_addr, addr))   ← checks CACHED tlb_addr
  tlb_hit_page computes:
    (addr & PAGE_MASK) == (tlb_addr & (PAGE_MASK | TLB_INVALID_MASK))
    LHS: 0xFFFFFFFFFFFFFFFF & 0xFFFFFFFFFFFFF000 = 0xFFFFFFFFFFFFF000
    RHS: 0xFFFFFFFFFFFFF7FF & 0xFFFFFFFFFFFFF800 = 0xFFFFFFFFFFFFF000
    → TRUE
  Because TLB_MMIO (bit 9) is absent from the mask, and because the stale
  all-1s sentinel happens to produce the same page-aligned value as the
  target address, the check passes. tlb_fill() is NOT called again.

Step 4 — Memory read
  paddr = entry->paddr | (addr & ~PAGE_MASK)
        = 0xFFFFFFFFFFFFFFFF | 0xFFF  ← entry->paddr is all-1s after flush
        = 0xFFFFFFFFFFFFFFFF
  mr = memory_mapping(uc, 0xFFFFFFFFFFFFFFFF)
     = the region just mapped by the hook (0xFFFFFFFFFFFFF000 page)
  mr != NULL → execution continues to the slow MMIO path:
    tlb_addr & ~TARGET_PAGE_MASK is non-zero → io_readx() called
    The iotlb entry at that slot (reset to -1 by tlb_flush) maps to
    section index 0 (io_mem_unassigned), which returns 0 unconditionally.
  CPU register gets 0 instead of the mapped value.
```

The `tlb_hit()` check is designed to detect a TLB miss for a *different*
page (large-page promotion, alias, etc.).  It is not designed to detect that
the entire TLB was flushed under it.  For addresses in the specific page
`0xFFFFFFFFFFFFF000`, the page-aligned bits of the all-1s stale sentinel
exactly equal the page-aligned bits of `addr`, so the check silently passes.

---

## Address sensitivity

**The bug does not affect arbitrary unmapped addresses.** It only fires for
accesses where `addr & PAGE_MASK == 0xFFFFFFFFFFFFF000`, i.e. addresses in
the range `[0xFFFFFFFFFFFFF000, 0xFFFFFFFFFFFFFFFF]`.

Why this specific range: after `tlb_flush`, every `CPUTLBEntry` is memset to
`-1` (all bits set).  The cached `tlb_addr` is derived from the pre-flush
`addr_read` value, which was `-1` for the unassigned page.  After masking:

```
tlb_addr = -1 & ~TLB_INVALID_MASK = 0xFFFFFFFFFFFFF7FF
tlb_addr & (PAGE_MASK | TLB_INVALID_MASK) = 0xFFFFFFFFFFFFF000
```

Only addresses whose `addr & PAGE_MASK` equals `0xFFFFFFFFFFFFF000` produce a
spurious hit.  For any other page (e.g. `0xDEAD0000`), the page-aligned bits
differ, `tlb_hit` correctly returns `false`, `tlb_fill` is called, and the
read succeeds normally.

---

## Minimal reproducer

Build and run: `bash bugs/unicorn-stale-mmio-tlb/run.sh`
(links against the project's Unicorn install at
`build/unicorn-install/`; full two-test version in `poc.c`)

```c
#include <unicorn/unicorn.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* Address in [0xFFFFFFFFFFFFF000, 0xFFFFFFFFFFFFFFFF] — the only range
 * that triggers the spurious tlb_hit.  0xFFFFFFFFFFFFFFFF is canonical
 * x86-64 (bits 48-63 == bit 47 == 1). */
#define TARGET_ADDR UINT64_C(0xFFFFFFFFFFFFFFFF)
#define CODE_BASE   UINT64_C(0x1000)
#define STACK_BASE  UINT64_C(0x7fff0000)

/* 48 B8 FF FF FF FF FF FF FF FF  mov rax, 0xFFFFFFFFFFFFFFFF
 * 8A 00                          mov al, byte [rax]
 * F4                             hlt  */
static const uint8_t CODE[] = {
    0x48, 0xB8, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x8A, 0x00,
    0xF4,
};

static bool on_unmapped(uc_engine *uc, uc_mem_type type,
                        uint64_t addr, int size, int64_t val, void *ud) {
    uint8_t page[4096];
    memset(page, 0xAB, sizeof(page));
    uint64_t pg = addr & ~UINT64_C(0xFFF);
    uc_mem_map(uc, pg, 0x1000, UC_PROT_ALL);
    uc_mem_write(uc, pg, page, 0x1000);
    return true;
}

int main(void) {
    uc_engine *uc;
    uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL);  /* required for UC_HOOK_TLB_FILL */

    uc_mem_map(uc, CODE_BASE,  0x1000,  UC_PROT_ALL);
    uc_mem_map(uc, STACK_BASE, 0x10000, UC_PROT_ALL);
    uc_mem_write(uc, CODE_BASE, CODE, sizeof(CODE));

    uint64_t rsp = STACK_BASE + 0x8000;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

    uc_hook hh;
    uc_hook_add(uc, &hh, UC_HOOK_MEM_READ_UNMAPPED, on_unmapped, NULL, 1, 0);

    uc_emu_start(uc, CODE_BASE, CODE_BASE + sizeof(CODE) - 1, 0, 0);

    uint64_t rax = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    printf("AL = 0x%02llx  (expected 0xAB)\n", (unsigned long long)(rax & 0xFF));
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
uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL);
uc_hook_add(uc, &hh, UC_HOOK_TLB_FILL, tlb_fill_hook, ctx, 1, 0);
```

The key ordering guarantee:

```
TLB miss
  → tlb_fill()
    → unicorn_fill_tlb()
      → UC_HOOK_TLB_FILL callback  ← uc_mem_map() here, RAM region registered
      → tlb_set_page()             ← address_space_translate_for_iotlb()
                                        finds the RAM region, prot != 0,
                                        addr_read = vaddr_page (non-MMIO)
  → load_helper fast-path: tlb_addr & ~PAGE_MASK == 0 → direct RAM read
```

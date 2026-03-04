/*
 * poc.c — Unicorn stale TLB_MMIO entry after uc_mem_map() in
 *         UC_HOOK_MEM_READ_UNMAPPED.
 *
 * See report.md for full root-cause analysis.
 *
 * ROOT CAUSE (brief):
 * ROOT CAUSE (brief):
 *   load_helper() caches `tlb_addr` from the TLB entry *before* firing the
 *   UC_HOOK_MEM_READ_UNMAPPED callback.  The callback calls uc_mem_map(),
 *   which calls tlb_flush() — clearing every TLB slot and resetting every
 *   CPUTLBEntry to all-0xFF.  On return, load_helper's post-hook tlb_hit()
 *   re-check passes spuriously:
 *
 *       tlb_hit_page checks:
 *           (addr & PAGE_MASK) == (tlb_addr & (PAGE_MASK | TLB_INVALID_MASK))
 *
 *   With prot=0 for an unassigned page, tlb_set_page stores addr_read = -1.
 *   After masking off TLB_INVALID_MASK (bit 11), the cached tlb_addr becomes
 *   0xFFFFFFFFFFFFF7FF, whose (PAGE_MASK | TLB_INVALID_MASK)-masked value is
 *   0xFFFFFFFFFFFFF000.  Any access whose (addr & PAGE_MASK) equals that
 *   sentinel — i.e. any address in [0xFFFFFFFFFFFFF000, 0xFFFFFFFFFFFFFFFF]
 *   — passes the check.  tlb_fill() is skipped; the iotlb still points to
 *   io_mem_unassigned; the CPU reads 0 instead of the mapped value.
 *
 *   So tlb_fill() is never called again, the stale (all-0xFF) iotlb entry
 *   is used, io_mem_unassigned fires, and the CPU reads 0 silently.
 *
 * TWO TESTS:
 *   1. [BUG]        UC_HOOK_MEM_READ_UNMAPPED + uc_mem_map() → AL = 0x00 (wrong)
 *   2. [WORKAROUND] UC_HOOK_TLB_FILL         + uc_mem_map() → AL = 0xAB (correct)
 *
 * Exit codes:
 *   0  bug reproduced AND workaround correct (expected on affected Unicorn)
 *   1  unexpected result — check Unicorn version or code address mapping
 */

#include <unicorn/unicorn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

/* ── Constants ────────────────────────────────────────────────────────────── */

/*
 * The bug only fires for addresses whose page-aligned bits equal the sentinel
 * value 0xFFFFFFFFFFFFF000 — the page that the all-1s TLB_INVALID entry
 * decodes to after masking.  Any address in [0xFFFFFFFFFFFFF000,
 * 0xFFFFFFFFFFFFFFFF] will trigger the stale-hit path.  We use the last byte
 * of that page as the most obviously-unmapped canonical address.
 *
 * 0xFFFFFFFFFFFFFFFF is canonical in x86-64 (bits 48-63 match bit 47 = 1).
 */
#define TARGET_ADDR  UINT64_C(0xFFFFFFFFFFFFFFFF)
/* Byte written into every cell of the newly-mapped page.
 * If the read returns this value, memory was read after mapping.
 * If it returns 0x00, the stale TLB bug fired. */
#define FILL_BYTE    0xAB

#define CODE_BASE    UINT64_C(0x1000)
#define STACK_BASE   UINT64_C(0x7fff0000)

/*
 * Machine code (x86-64):
 *
 *   48 B8 FF FF FF FF FF FF FF FF   mov rax, 0xFFFFFFFFFFFFFFFF
 *   8A 00                            mov al, byte [rax]
 *   F4                               hlt  ← uc_emu_start "until" points here;
 *                                         it is never executed
 */
#define A(n) ((uint8_t)((TARGET_ADDR >> (8*(n))) & 0xFF))
static const uint8_t CODE[] = {
    0x48, 0xB8, A(0), A(1), A(2), A(3), A(4), A(5), A(6), A(7),
    0x8A, 0x00,
    0xF4,
};
#undef A

/* uc_emu_start "until" = address of HLT = last byte; Unicorn stops when
 * PC reaches it (before executing it). */
#define CODE_UNTIL   (CODE_BASE + sizeof(CODE) - 1)

/* ── Shared helpers ───────────────────────────────────────────────────────── */

static void fill_and_map(uc_engine *uc, uint64_t page_base) {
    uint8_t page[0x1000];
    memset(page, FILL_BYTE, sizeof(page));
    uc_err err = uc_mem_map(uc, page_base, 0x1000, UC_PROT_ALL);
    if (err == UC_ERR_OK)
        uc_mem_write(uc, page_base, page, sizeof(page));
    /* UC_ERR_MAP: already mapped — leave contents as-is */
}

static uc_engine *make_uc(void) {
    uc_engine *uc = NULL;
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "uc_open failed: %s\n", uc_strerror(err));
        return NULL;
    }
    uc_ctl_tlb_mode(uc, UC_TLB_VIRTUAL);

    uc_mem_map(uc, CODE_BASE,  0x1000,  UC_PROT_ALL);
    uc_mem_map(uc, STACK_BASE, 0x10000, UC_PROT_ALL);
    uc_mem_write(uc, CODE_BASE, CODE, sizeof(CODE));

    uint64_t rsp = STACK_BASE + 0x8000;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
    return uc;
}

/* ── Test 1: buggy path ───────────────────────────────────────────────────── */

static bool bug_unmapped_cb(uc_engine *uc, uc_mem_type type,
                             uint64_t addr, int size, int64_t val, void *ud) {
    (void)type; (void)size; (void)val; (void)ud;
    fill_and_map(uc, addr & ~UINT64_C(0xFFF));
    /*
     * Returning true tells Unicorn the fault was "handled".
     * load_helper then checks tlb_hit() against the *stale* cached tlb_addr —
     * the check always passes because TLB_MMIO is stripped from the comparison,
     * so tlb_fill() is never called again, the iotlb entry is garbage (all-0xFF
     * after tlb_flush), and the CPU reads 0 instead of FILL_BYTE.
     */
    return true;
}

static int test_bug(void) {
    uc_engine *uc = make_uc();
    if (!uc) return -1;

    uc_hook hh;
    uc_hook_add(uc, &hh, UC_HOOK_MEM_READ_UNMAPPED, bug_unmapped_cb,
                NULL, 1, 0);

    uc_emu_start(uc, CODE_BASE, CODE_UNTIL, 0, 0);

    uint64_t rax = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_close(uc);

    uint8_t al = (uint8_t)(rax & 0xFF);
    printf("[BUG]        AL = 0x%02x  (expected 0x%02x)  %s\n",
           al, FILL_BYTE,
           al == 0x00     ? "REPRODUCED — stale MMIO TLB bug confirmed" :
           al == FILL_BYTE ? "NOT REPRODUCED — Unicorn may have been patched" :
                             "UNEXPECTED value");
    return (al == 0x00) ? 0 : 1; /* 0 = bug confirmed */
}

/* ── Test 2: workaround via UC_HOOK_TLB_FILL ─────────────────────────────── */

/*
 * UC_HOOK_TLB_FILL fires *inside* unicorn_fill_tlb(), before tlb_set_page()
 * runs.  Mapping memory here means tlb_set_page() finds a real RAM region
 * (is_ram = true), produces a non-MMIO TLB entry, and load_helper takes the
 * normal fast-path RAM read.  No stale-entry problem exists because we never
 * reach the UC_HOOK_MEM_READ_UNMAPPED path at all.
 */
static bool tlb_fill_cb(uc_engine *uc, uint64_t addr,
                         uc_mem_type type, uc_tlb_entry *result,
                         void *user_data) {
    (void)type; (void)user_data;
    /* addr is page-aligned when this hook fires */
    fill_and_map(uc, addr);
    result->paddr = addr;       /* identity mapping */
    result->perms = UC_PROT_ALL;
    return true;
}

static int test_workaround(void) {
    uc_engine *uc = make_uc();
    if (!uc) return -1;

    uc_hook hh;
    uc_hook_add(uc, &hh, UC_HOOK_TLB_FILL, tlb_fill_cb, NULL, 1, 0);

    uc_emu_start(uc, CODE_BASE, CODE_UNTIL, 0, 0);

    uint64_t rax = 0;
    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_close(uc);

    uint8_t al = (uint8_t)(rax & 0xFF);
    printf("[WORKAROUND] AL = 0x%02x  (expected 0x%02x)  %s\n",
           al, FILL_BYTE,
           al == FILL_BYTE ? "PASS" : "FAIL");
    return (al == FILL_BYTE) ? 0 : 1;
}

/* ── Entry point ──────────────────────────────────────────────────────────── */

int main(void) {
    printf("Unicorn stale TLB_MMIO POC\n");
    printf("  Target address: 0x%016llx\n", (unsigned long long)TARGET_ADDR);
    printf("  Fill byte:      0x%02x\n\n", FILL_BYTE);

    int bug_rc        = test_bug();
    int workaround_rc = test_workaround();

    printf("\nSummary:\n");
    printf("  Bug reproduced:     %s\n",
           bug_rc == 0 ? "YES" : "NO  (check Unicorn version)");
    printf("  Workaround correct: %s\n",
           workaround_rc == 0 ? "YES" : "NO");

    /* Canonical success: bug visible AND workaround fixes it */
    return (bug_rc == 0 && workaround_rc == 0) ? 0 : 1;
}

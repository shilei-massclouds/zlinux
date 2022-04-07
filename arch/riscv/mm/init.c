// SPDX-License-Identifier: GPL-2.0-only

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sizes.h>
#include <linux/export.h>

#include <asm/sections.h>
#include <asm/page.h>

#include "../kernel/head.h"

#define MAX_EARLY_MAPPING_SIZE  SZ_128M

unsigned long va_pa_offset;
EXPORT_SYMBOL(va_pa_offset);

unsigned long pfn_base;
EXPORT_SYMBOL(pfn_base);

pgd_t trampoline_pg_dir[PTRS_PER_PGD] __page_aligned_bss;
pmd_t trampoline_pmd[PTRS_PER_PMD] __page_aligned_bss;

pmd_t fixmap_pmd[PTRS_PER_PMD] __page_aligned_bss;

//pgd_t early_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);

//static bool mmu_enabled;

/*
static phys_addr_t __init alloc_pmd(uintptr_t va)
{
    uintptr_t pmd_num;

    if (mmu_enabled)
        return memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);

    pmd_num = (va - PAGE_OFFSET) >> PGDIR_SHIFT;
    BUG_ON(pmd_num >= NUM_EARLY_PMDS);
    return (uintptr_t)&early_pmd[pmd_num * PTRS_PER_PMD];
}
*/

static void __init
create_pmd_mapping(pmd_t *pmdp, uintptr_t va, phys_addr_t pa,
                   phys_addr_t sz, pgprot_t prot)
{
    /*
    pte_t *ptep;
    phys_addr_t pte_phys;
    */
    uintptr_t pmd_idx = pmd_index(va);

    if (sz == PMD_SIZE) {
        if (pmd_none(pmdp[pmd_idx]))
            pmdp[pmd_idx] = pfn_pmd(PFN_DOWN(pa), prot);
        return;
    }

    // panic
}

#define pgd_next_t              pmd_t
#define alloc_pgd_next(__va)    alloc_pmd(__va)
#define fixmap_pgd_next         fixmap_pmd

static uintptr_t __init best_map_size(phys_addr_t base, phys_addr_t size)
{
    /* Upgrade to PMD_SIZE mappings whenever possible */
    if ((base & (PMD_SIZE - 1)) || (size & (PMD_SIZE - 1)))
        return PAGE_SIZE;

    return PMD_SIZE;
}

static void __init
create_pgd_mapping(pgd_t *pgdp, uintptr_t va, phys_addr_t pa, phys_addr_t sz,
                   pgprot_t prot)
{
    /*
    pgd_next_t *nextp;
    phys_addr_t next_phys;
    */
    uintptr_t pgd_idx = pgd_index(va);

    if (sz == PGDIR_SIZE) {
        if (pgd_val(pgdp[pgd_idx]) == 0)
            pgdp[pgd_idx] = pfn_pgd(PFN_DOWN(pa), prot);
        return;
    }

    /*
    if (pgd_val(pgdp[pgd_idx]) == 0) {
        next_phys = alloc_pgd_next(va);
        pgdp[pgd_idx] = pfn_pgd(PFN_DOWN(next_phys), PAGE_TABLE);
        nextp = get_pgd_next_virt(next_phys);
        memset(nextp, 0, PAGE_SIZE);
    } else {
        next_phys = PFN_PHYS(_pgd_pfn(pgdp[pgd_idx]));
        nextp = get_pgd_next_virt(next_phys);
    }

    create_pgd_next_mapping(nextp, va, pa, sz, prot);
    */
}

asmlinkage void __init setup_vm(uintptr_t dtb_pa)
{
    //uintptr_t va, end_va;
    uintptr_t load_pa = (uintptr_t)(&_start);
    uintptr_t load_sz = (uintptr_t)(&_end) - load_pa;
    uintptr_t map_size = best_map_size(load_pa, MAX_EARLY_MAPPING_SIZE);

    va_pa_offset = PAGE_OFFSET - load_pa;
    pfn_base = PFN_DOWN(load_pa);

    /*
     * Enforce boot alignment requirements of RV32 and
     * RV64 by only allowing PMD or PGD mappings.
     */
    BUG_ON(map_size == PAGE_SIZE);

    /* Sanity check alignment and size */
    BUG_ON((PAGE_OFFSET % PGDIR_SIZE) != 0);
    BUG_ON((load_pa % map_size) != 0);
    BUG_ON(load_sz > MAX_EARLY_MAPPING_SIZE);

    /* Setup early PGD for fixmap */
    /*
    create_pgd_mapping(early_pg_dir, FIXADDR_START,
                       (uintptr_t)fixmap_pgd_next, PGDIR_SIZE, PAGE_TABLE);
                       */

    /* Setup trampoline PGD and PMD */
    create_pgd_mapping(trampoline_pg_dir, PAGE_OFFSET,
                       (uintptr_t)trampoline_pmd, PGDIR_SIZE, PAGE_TABLE);
    create_pmd_mapping(trampoline_pmd, PAGE_OFFSET,
                       load_pa, PMD_SIZE, PAGE_KERNEL_EXEC);

    /*
     * Setup early PGD covering entire kernel which will allows
     * us to reach paging_init(). We map all memory banks later
     * in setup_vm_final() below.
     */
    /*
    end_va = PAGE_OFFSET + load_sz;
    for (va = PAGE_OFFSET; va < end_va; va += map_size)
        create_pgd_mapping(early_pg_dir, va, load_pa + (va - PAGE_OFFSET),
                           map_size, PAGE_KERNEL_EXEC);
                           */

}

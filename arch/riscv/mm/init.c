// SPDX-License-Identifier: GPL-2.0-only

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sizes.h>
#include <linux/export.h>

#include <linux/kernel.h>

#include <asm/fixmap.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/page.h>
#include <asm/string.h>

#include "../kernel/head.h"

#define MAX_EARLY_MAPPING_SIZE  SZ_128M

void *dtb_early_va;
static phys_addr_t dtb_early_pa __initdata;

unsigned long va_pa_offset;
EXPORT_SYMBOL(va_pa_offset);

unsigned long pfn_base;
EXPORT_SYMBOL(pfn_base);

pgd_t swapper_pg_dir[PTRS_PER_PGD] __page_aligned_bss;

pgd_t trampoline_pg_dir[PTRS_PER_PGD] __page_aligned_bss;
pmd_t trampoline_pmd[PTRS_PER_PMD] __page_aligned_bss;

pmd_t fixmap_pmd[PTRS_PER_PMD] __page_aligned_bss;
pte_t fixmap_pte[PTRS_PER_PTE] __page_aligned_bss;

pmd_t early_pmd[PTRS_PER_PMD] __initdata __aligned(PAGE_SIZE);
pgd_t early_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);

static bool mmu_enabled;

void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot)
{
    unsigned long addr = __fix_to_virt(idx);
    pte_t *ptep;

    BUG_ON(idx <= FIX_HOLE || idx >= __end_of_fixed_addresses);

    ptep = &fixmap_pte[pte_index(addr)];

    if (pgprot_val(prot)) {
        set_pte(ptep, pfn_pte(phys >> PAGE_SHIFT, prot));
    } else {
        pte_clear(&init_mm, addr, ptep);
        local_flush_tlb_page(addr);
    }
}

static pte_t *__init get_pte_virt(phys_addr_t pa)
{
    if (mmu_enabled) {
        clear_fixmap(FIX_PTE);
        return (pte_t *)set_fixmap_offset(FIX_PTE, pa);
    } else {
        return (pte_t *)((uintptr_t)pa);
    }
}

static phys_addr_t __init alloc_pte(void)
{
    /*
     * We only create PMD or PGD early mappings so we
     * should never reach here with MMU disabled.
     */
    BUG_ON(!mmu_enabled);

    panic("memblock_phys_alloc");
    //return memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
}

static void __init
create_pte_mapping(pte_t *ptep, uintptr_t va, phys_addr_t pa,
                   phys_addr_t sz, pgprot_t prot)
{
    uintptr_t pte_idx = pte_index(va);

    BUG_ON(sz != PAGE_SIZE);

    if (pte_none(ptep[pte_idx]))
        ptep[pte_idx] = pfn_pte(PFN_DOWN(pa), prot);
}

static pmd_t *__init get_pmd_virt(phys_addr_t pa)
{
    if (mmu_enabled) {
        clear_fixmap(FIX_PMD);
        return (pmd_t *)set_fixmap_offset(FIX_PMD, pa);
    } else {
        return (pmd_t *)((uintptr_t)pa);
    }
}

static phys_addr_t __init alloc_pmd(void)
{
    if (mmu_enabled)
        panic("memblock_phys_alloc");
        //return memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);

    return (uintptr_t)early_pmd;
}

static void __init
create_pmd_mapping(pmd_t *pmdp, uintptr_t va, phys_addr_t pa,
                   phys_addr_t sz, pgprot_t prot)
{
    pte_t *ptep;
    phys_addr_t pte_phys;
    uintptr_t pmd_idx = pmd_index(va);

    if (sz == PMD_SIZE) {
        if (pmd_none(pmdp[pmd_idx]))
            pmdp[pmd_idx] = pfn_pmd(PFN_DOWN(pa), prot);
        return;
    }

    if (pmd_none(pmdp[pmd_idx])) {
        pte_phys = alloc_pte();
        pmdp[pmd_idx] = pfn_pmd(PFN_DOWN(pte_phys), PAGE_TABLE);
        ptep = get_pte_virt(pte_phys);
        memset(ptep, 0, PAGE_SIZE);
    } else {
        pte_phys = PFN_PHYS(_pmd_pfn(pmdp[pmd_idx]));
        ptep = get_pte_virt(pte_phys);
    }

    create_pte_mapping(ptep, va, pa, sz, prot);
}

#define pgd_next_t              pmd_t
#define alloc_pgd_next          alloc_pmd
#define get_pgd_next_virt(__pa) get_pmd_virt(__pa)
#define fixmap_pgd_next         fixmap_pmd

#define create_pgd_next_mapping(__nextp, __va, __pa, __sz, __prot) \
    create_pmd_mapping(__nextp, __va, __pa, __sz, __prot)

static uintptr_t __init best_map_size(phys_addr_t base, phys_addr_t size)
{
    /* Upgrade to PMD_SIZE mappings whenever possible */
    if ((base & (PMD_SIZE - 1)) || (size & (PMD_SIZE - 1)))
        return PAGE_SIZE;

    return PMD_SIZE;
}

static void __init
create_pgd_mapping(pgd_t *pgdp, uintptr_t va, phys_addr_t pa,
                   phys_addr_t sz, pgprot_t prot)
{
    pgd_next_t *nextp;
    phys_addr_t next_phys;
    uintptr_t pgd_idx = pgd_index(va);

    if (sz == PGDIR_SIZE) {
        if (pgd_val(pgdp[pgd_idx]) == 0)
            pgdp[pgd_idx] = pfn_pgd(PFN_DOWN(pa), prot);
        return;
    }

    if (pgd_val(pgdp[pgd_idx]) == 0) {
        next_phys = alloc_pgd_next();
        pgdp[pgd_idx] = pfn_pgd(PFN_DOWN(next_phys), PAGE_TABLE);
        nextp = get_pgd_next_virt(next_phys);
        memset(nextp, 0, PAGE_SIZE);
    } else {
        next_phys = PFN_PHYS(_pgd_pfn(pgdp[pgd_idx]));
        nextp = get_pgd_next_virt(next_phys);
    }

    create_pgd_next_mapping(nextp, va, pa, sz, prot);
}

asmlinkage void __init setup_vm(uintptr_t dtb_pa)
{
    uintptr_t va, end_va;
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
    create_pgd_mapping(early_pg_dir, FIXADDR_START,
                       (uintptr_t)fixmap_pgd_next, PGDIR_SIZE, PAGE_TABLE);

    /* Setup fixmap PMD */
    create_pmd_mapping(fixmap_pmd, FIXADDR_START,
                       (uintptr_t)fixmap_pte, PMD_SIZE, PAGE_TABLE);

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
    end_va = PAGE_OFFSET + load_sz;
    for (va = PAGE_OFFSET; va < end_va; va += map_size)
        create_pgd_mapping(early_pg_dir, va, load_pa + (va - PAGE_OFFSET),
                           map_size, PAGE_KERNEL_EXEC);

    /* Create fixed mapping for early FDT parsing */
    end_va = __fix_to_virt(FIX_FDT) + FIX_FDT_SIZE;
    for (va = __fix_to_virt(FIX_FDT); va < end_va; va += PAGE_SIZE)
        create_pte_mapping(fixmap_pte,
                           va, dtb_pa + (va - __fix_to_virt(FIX_FDT)),
                           PAGE_SIZE, PAGE_KERNEL);

    /* Save pointer to DTB for early FDT parsing */
    dtb_early_va = (void *)fix_to_virt(FIX_FDT) + (dtb_pa & ~PAGE_MASK);
    /* Save physical address for memblock reservation */
    dtb_early_pa = dtb_pa;
}

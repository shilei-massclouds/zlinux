/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2009 Chen Liqin <liqin.chen@sunplusct.com>
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_PGALLOC_H
#define _ASM_RISCV_PGALLOC_H

#include <linux/mm.h>
//#include <asm/tlb.h>

#define __HAVE_ARCH_PUD_ALLOC_ONE
#define __HAVE_ARCH_PUD_FREE
#include <asm-generic/pgalloc.h>

static inline void pmd_populate_kernel(struct mm_struct *mm,
                                       pmd_t *pmd, pte_t *pte)
{
    unsigned long pfn = virt_to_pfn(pte);

    set_pmd(pmd, __pmd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
}

#define p4d_alloc_one p4d_alloc_one
static inline p4d_t *p4d_alloc_one(struct mm_struct *mm, unsigned long addr)
{
    if (pgtable_l5_enabled) {
        gfp_t gfp = GFP_PGTABLE_USER;

        if (mm == &init_mm)
            gfp = GFP_PGTABLE_KERNEL;
        return (p4d_t *)get_zeroed_page(gfp);
    }

    return NULL;
}

static inline void __p4d_free(struct mm_struct *mm, p4d_t *p4d)
{
    BUG_ON((unsigned long)p4d & (PAGE_SIZE-1));
    free_page((unsigned long)p4d);
}

#define p4d_free p4d_free
static inline void p4d_free(struct mm_struct *mm, p4d_t *p4d)
{
    if (pgtable_l5_enabled)
        __p4d_free(mm, p4d);
}

static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
{
    if (pgtable_l5_enabled) {
        unsigned long pfn = virt_to_pfn(p4d);

        set_pgd(pgd, __pgd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
    }
}

static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
    unsigned long pfn = virt_to_pfn(pmd);

    set_pud(pud, __pud((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
}

static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
{
    if (pgtable_l4_enabled) {
        unsigned long pfn = virt_to_pfn(pud);

        set_p4d(p4d, __p4d((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
    }
}

static inline void pmd_populate(struct mm_struct *mm, pmd_t *pmd, pgtable_t pte)
{
    unsigned long pfn = virt_to_pfn(page_address(pte));

    set_pmd(pmd, __pmd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
}

#define pud_alloc_one pud_alloc_one
static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
    if (pgtable_l4_enabled)
        return __pud_alloc_one(mm, addr);

    return NULL;
}

#define pud_free pud_free
static inline void pud_free(struct mm_struct *mm, pud_t *pud)
{
    if (pgtable_l4_enabled)
        __pud_free(mm, pud);
}

#endif /* _ASM_RISCV_PGALLOC_H */

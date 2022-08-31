// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 SiFive
 */

#include <linux/pagewalk.h>
#include <linux/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/bitops.h>
#include <asm/set_memory.h>

struct pageattr_masks {
    pgprot_t set_mask;
    pgprot_t clear_mask;
};

static unsigned long set_pageattr_masks(unsigned long val, struct mm_walk *walk)
{
    struct pageattr_masks *masks = walk->private;
    unsigned long new_val = val;

    new_val &= ~(pgprot_val(masks->clear_mask));
    new_val |= (pgprot_val(masks->set_mask));

    return new_val;
}

static int pageattr_pgd_entry(pgd_t *pgd, unsigned long addr,
                              unsigned long next, struct mm_walk *walk)
{
    pgd_t val = READ_ONCE(*pgd);

    if (pgd_leaf(val)) {
        val = __pgd(set_pageattr_masks(pgd_val(val), walk));
        set_pgd(pgd, val);
    }

    return 0;
}

static int pageattr_p4d_entry(p4d_t *p4d, unsigned long addr,
                              unsigned long next, struct mm_walk *walk)
{
    p4d_t val = READ_ONCE(*p4d);

    if (p4d_leaf(val)) {
        val = __p4d(set_pageattr_masks(p4d_val(val), walk));
        set_p4d(p4d, val);
    }

    return 0;
}

static int pageattr_pud_entry(pud_t *pud, unsigned long addr,
                              unsigned long next, struct mm_walk *walk)
{
    pud_t val = READ_ONCE(*pud);

    if (pud_leaf(val)) {
        val = __pud(set_pageattr_masks(pud_val(val), walk));
        set_pud(pud, val);
    }

    return 0;
}

static int pageattr_pmd_entry(pmd_t *pmd, unsigned long addr,
                              unsigned long next, struct mm_walk *walk)
{
    pmd_t val = READ_ONCE(*pmd);

    if (pmd_leaf(val)) {
        val = __pmd(set_pageattr_masks(pmd_val(val), walk));
        set_pmd(pmd, val);
    }

    return 0;
}

static int pageattr_pte_entry(pte_t *pte, unsigned long addr,
                              unsigned long next, struct mm_walk *walk)
{
    pte_t val = READ_ONCE(*pte);

    val = __pte(set_pageattr_masks(pte_val(val), walk));
    set_pte(pte, val);

    return 0;
}

static int pageattr_pte_hole(unsigned long addr, unsigned long next,
                             int depth, struct mm_walk *walk)
{
    /* Nothing to do here */
    return 0;
}

static const struct mm_walk_ops pageattr_ops = {
    .pgd_entry = pageattr_pgd_entry,
    .p4d_entry = pageattr_p4d_entry,
    .pud_entry = pageattr_pud_entry,
    .pmd_entry = pageattr_pmd_entry,
    .pte_entry = pageattr_pte_entry,
    .pte_hole = pageattr_pte_hole,
};

static int __set_memory(unsigned long addr, int numpages, pgprot_t set_mask,
                        pgprot_t clear_mask)
{
    int ret;
    unsigned long start = addr;
    unsigned long end = start + PAGE_SIZE * numpages;
    struct pageattr_masks masks = {
        .set_mask = set_mask,
        .clear_mask = clear_mask
    };

    if (!numpages)
        return 0;

    mmap_read_lock(&init_mm);
    ret = walk_page_range_novma(&init_mm, start, end, &pageattr_ops, NULL,
                                &masks);
    mmap_read_unlock(&init_mm);

    flush_tlb_kernel_range(start, end);

    return ret;
}

int set_memory_rw(unsigned long addr, int numpages)
{
    return __set_memory(addr, numpages, __pgprot(_PAGE_READ | _PAGE_WRITE),
                        __pgprot(0));
}

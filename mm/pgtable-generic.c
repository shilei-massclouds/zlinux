// SPDX-License-Identifier: GPL-2.0
/*
 *  mm/pgtable-generic.c
 *
 *  Generic pgtable methods declared in linux/pgtable.h
 *
 *  Copyright (C) 2010  Linus Torvalds
 */

#if 0
#include <linux/pagemap.h>
#include <linux/hugetlb.h>
#endif
#include <linux/pgtable.h>
#if 0
#include <linux/mm_inline.h>
#include <asm/tlb.h>
#endif

/*
 * If a p?d_bad entry is found while walking page tables, report
 * the error, before resetting entry to p?d_none.  Usually (but
 * very seldom) called out from the p?d_none_or_clear_bad macros.
 */

void pgd_clear_bad(pgd_t *pgd)
{
    pgd_ERROR(*pgd);
    pgd_clear(pgd);
}

void p4d_clear_bad(p4d_t *p4d)
{
    p4d_ERROR(*p4d);
    p4d_clear(p4d);
}

/*
 * Note that the pmd variant below can't be stub'ed out just as for p4d/pud
 * above. pmd folding is special and typically pmd_* macros refer to upper
 * level even when folded
 */
void pmd_clear_bad(pmd_t *pmd)
{
    pmd_ERROR(*pmd);
    pmd_clear(pmd);
}

void pud_clear_bad(pud_t *pud)
{
    pud_ERROR(*pud);
    pud_clear(pud);
}

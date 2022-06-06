/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_PGTABLE_64_H
#define _ASM_RISCV_PGTABLE_64_H

#include <linux/const.h>

extern bool pgtable_l4_enabled;
extern bool pgtable_l5_enabled;

#define PGDIR_SHIFT_L3  30
#define PGDIR_SHIFT_L4  39
#define PGDIR_SHIFT_L5  48

#define PGDIR_SHIFT     PGDIR_SHIFT_L5
/* Size of region mapped by a page global directory */
#define PGDIR_SIZE      (_AC(1, UL) << PGDIR_SHIFT)
#define PGDIR_MASK      (~(PGDIR_SIZE - 1))

/* p4d is folded into pgd in case of 4-level page table */
#define P4D_SHIFT      39
#define P4D_SIZE       (_AC(1, UL) << P4D_SHIFT)
#define P4D_MASK       (~(P4D_SIZE - 1))

/* pud is folded into pgd in case of 3-level page table */
#define PUD_SHIFT      30
#define PUD_SIZE       (_AC(1, UL) << PUD_SHIFT)
#define PUD_MASK       (~(PUD_SIZE - 1))

#define PMD_SHIFT       21
/* Size of region mapped by a page middle directory */
#define PMD_SIZE        (_AC(1, UL) << PMD_SHIFT)
#define PMD_MASK        (~(PMD_SIZE - 1))

/* Page 4th Directory entry */
typedef struct {
    unsigned long p4d;
} p4d_t;

#define p4d_val(x)      ((x).p4d)
#define __p4d(x)        ((p4d_t) { (x) })
#define PTRS_PER_P4D    (PAGE_SIZE / sizeof(p4d_t))

/* Page Upper Directory entry */
typedef struct {
    unsigned long pud;
} pud_t;

#define pud_val(x)      ((x).pud)
#define __pud(x)        ((pud_t) { (x) })
#define PTRS_PER_PUD    (PAGE_SIZE / sizeof(pud_t))

/* Page Middle Directory entry */
typedef struct {
    unsigned long pmd;
} pmd_t;

#define pmd_val(x)      ((x).pmd)
#define __pmd(x)        ((pmd_t) { (x) })
#define PTRS_PER_PMD    (PAGE_SIZE / sizeof(pmd_t))

static inline pmd_t pfn_pmd(unsigned long pfn, pgprot_t prot)
{
    return __pmd((pfn << _PAGE_PFN_SHIFT) | pgprot_val(prot));
}

static inline unsigned long _pmd_pfn(pmd_t pmd)
{
    return pmd_val(pmd) >> _PAGE_PFN_SHIFT;
}

#define p4d_index(addr) (((addr) >> P4D_SHIFT) & (PTRS_PER_P4D - 1))

#define pud_index(addr) (((addr) >> PUD_SHIFT) & (PTRS_PER_PUD - 1))

static inline p4d_t pfn_p4d(unsigned long pfn, pgprot_t prot)
{
    return __p4d((pfn << _PAGE_PFN_SHIFT) | pgprot_val(prot));
}

static inline unsigned long _p4d_pfn(p4d_t p4d)
{
    return p4d_val(p4d) >> _PAGE_PFN_SHIFT;
}

static inline pud_t pfn_pud(unsigned long pfn, pgprot_t prot)
{
    return __pud((pfn << _PAGE_PFN_SHIFT) | pgprot_val(prot));
}

static inline unsigned long _pud_pfn(pud_t pud)
{
    return pud_val(pud) >> _PAGE_PFN_SHIFT;
}

#endif /* _ASM_RISCV_PGTABLE_64_H */

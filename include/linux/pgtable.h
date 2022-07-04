/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PGTABLE_H
#define _LINUX_PGTABLE_H

#include <linux/pfn.h>
#include <asm/pgtable.h>

#ifndef __ASSEMBLY__

static inline unsigned long pte_index(unsigned long address)
{
    return (address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
}

#ifndef pmd_index
static inline unsigned long pmd_index(unsigned long address)
{
    return (address >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
}
#define pmd_index pmd_index
#endif

#ifndef pgd_index
/* Must be a compile-time constant, so implement it as a macro */
#define pgd_index(a)  (((a) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#endif

static inline pgd_t *pgd_offset_pgd(pgd_t *pgd, unsigned long address)
{
    return (pgd + pgd_index(address));
};

/*
 * a shortcut to get a pgd_t in a given mm
 */
#ifndef pgd_offset
#define pgd_offset(mm, address) pgd_offset_pgd((mm)->pgd, (address))
#endif

/*
 * a shortcut which implies the use of the kernel's pgd, instead
 * of a process's
 */
#ifndef pgd_offset_k
#define pgd_offset_k(address)   pgd_offset(&init_mm, (address))
#endif

/*
 * When walking page tables, get the address of the next boundary,
 * or the end address of the range if that comes earlier.  Although no
 * vma end wraps to 0, rounded up __boundary may wrap to 0 throughout.
 */

#define pgd_addr_end(addr, end)                     \
({  unsigned long __boundary = ((addr) + PGDIR_SIZE) & PGDIR_MASK;  \
    (__boundary - 1 < (end) - 1)? __boundary: (end);        \
})

#ifndef p4d_addr_end
#define p4d_addr_end(addr, end)                     \
({  unsigned long __boundary = ((addr) + P4D_SIZE) & P4D_MASK;  \
    (__boundary - 1 < (end) - 1)? __boundary: (end);        \
})
#endif

#ifndef pud_addr_end
#define pud_addr_end(addr, end)                     \
({  unsigned long __boundary = ((addr) + PUD_SIZE) & PUD_MASK;  \
    (__boundary - 1 < (end) - 1)? __boundary: (end);        \
})
#endif

#ifndef pmd_addr_end
#define pmd_addr_end(addr, end)                     \
({  unsigned long __boundary = ((addr) + PMD_SIZE) & PMD_MASK;  \
    (__boundary - 1 < (end) - 1)? __boundary: (end);        \
})
#endif

/*
 * Page Table Modification bits for pgtbl_mod_mask.
 *
 * These are used by the p?d_alloc_track*() set of functions an in the generic
 * vmalloc/ioremap code to track at which page-table levels entries have been
 * modified. Based on that the code can better decide when vmalloc and ioremap
 * mapping changes need to be synchronized to other page-tables in the system.
 */
#define     __PGTBL_PGD_MODIFIED    0
#define     __PGTBL_P4D_MODIFIED    1
#define     __PGTBL_PUD_MODIFIED    2
#define     __PGTBL_PMD_MODIFIED    3
#define     __PGTBL_PTE_MODIFIED    4

#define     PGTBL_PGD_MODIFIED  BIT(__PGTBL_PGD_MODIFIED)
#define     PGTBL_P4D_MODIFIED  BIT(__PGTBL_P4D_MODIFIED)
#define     PGTBL_PUD_MODIFIED  BIT(__PGTBL_PUD_MODIFIED)
#define     PGTBL_PMD_MODIFIED  BIT(__PGTBL_PMD_MODIFIED)
#define     PGTBL_PTE_MODIFIED  BIT(__PGTBL_PTE_MODIFIED)

/* Page-Table Modification Mask */
typedef unsigned int pgtbl_mod_mask;

/*
 * When walking page tables, we usually want to skip any p?d_none entries;
 * and any p?d_bad entries - reporting the error before resetting to none.
 * Do the tests inline, but report and clear the bad entry in mm/memory.c.
 */
void pgd_clear_bad(pgd_t *);

void p4d_clear_bad(p4d_t *);

void pud_clear_bad(pud_t *);

void pmd_clear_bad(pmd_t *);

static inline int pgd_none_or_clear_bad(pgd_t *pgd)
{
    if (pgd_none(*pgd))
        return 1;
    if (unlikely(pgd_bad(*pgd))) {
        pgd_clear_bad(pgd);
        return 1;
    }
    return 0;
}

static inline int p4d_none_or_clear_bad(p4d_t *p4d)
{
    if (p4d_none(*p4d))
        return 1;
    if (unlikely(p4d_bad(*p4d))) {
        p4d_clear_bad(p4d);
        return 1;
    }
    return 0;
}

static inline int pud_none_or_clear_bad(pud_t *pud)
{
    if (pud_none(*pud))
        return 1;
    if (unlikely(pud_bad(*pud))) {
        pud_clear_bad(pud);
        return 1;
    }
    return 0;
}

static inline int pmd_none_or_clear_bad(pmd_t *pmd)
{
    if (pmd_none(*pmd))
        return 1;
    if (unlikely(pmd_bad(*pmd))) {
        pmd_clear_bad(pmd);
        return 1;
    }
    return 0;
}

#ifndef pte_offset_kernel
static inline pte_t *pte_offset_kernel(pmd_t *pmd, unsigned long address)
{
    return (pte_t *)pmd_page_vaddr(*pmd) + pte_index(address);
}
#define pte_offset_kernel pte_offset_kernel
#endif

/* Find an entry in the second-level page table.. */
#ifndef pmd_offset
static inline pmd_t *pmd_offset(pud_t *pud, unsigned long address)
{
    return pud_pgtable(*pud) + pmd_index(address);
}
#define pmd_offset pmd_offset
#endif

#ifndef pud_offset
static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
{
    return p4d_pgtable(*p4d) + pud_index(address);
}
#define pud_offset pud_offset
#endif

/*
 * No-op macros that just return the current protection value. Defined here
 * because these macros can be used even if CONFIG_MMU is not defined.
 */

#ifndef pgprot_nx
#define pgprot_nx(prot) (prot)
#endif

static inline int p4d_set_huge(p4d_t *p4d, phys_addr_t addr, pgprot_t prot)
{
    return 0;
}
static inline int pud_set_huge(pud_t *pud, phys_addr_t addr, pgprot_t prot)
{
    return 0;
}
static inline int pmd_set_huge(pmd_t *pmd, phys_addr_t addr, pgprot_t prot)
{
    return 0;
}
static inline int p4d_clear_huge(p4d_t *p4d)
{
    return 0;
}
static inline int pud_clear_huge(pud_t *pud)
{
    return 0;
}
static inline int pmd_clear_huge(pmd_t *pmd)
{
    return 0;
}
static inline int p4d_free_pud_page(p4d_t *p4d, unsigned long addr)
{
    return 0;
}
static inline int pud_free_pmd_page(pud_t *pud, unsigned long addr)
{
    return 0;
}
static inline int pmd_free_pte_page(pmd_t *pmd, unsigned long addr)
{
    return 0;
}

#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_PGTABLE_H */

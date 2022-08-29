/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_HUGETLB_H
#define _ASM_GENERIC_HUGETLB_H

#ifndef __HAVE_ARCH_HUGE_SET_HUGE_PTE_AT
static inline void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
                                   pte_t *ptep, pte_t pte)
{
    set_pte_at(mm, addr, ptep, pte);
}
#endif

#ifndef __HAVE_ARCH_HUGETLB_FREE_PGD_RANGE
static inline void hugetlb_free_pgd_range(struct mmu_gather *tlb,
                                          unsigned long addr,
                                          unsigned long end,
                                          unsigned long floor,
                                          unsigned long ceiling)
{
    free_pgd_range(tlb, addr, end, floor, ceiling);
}
#endif

#endif /* _ASM_GENERIC_HUGETLB_H */

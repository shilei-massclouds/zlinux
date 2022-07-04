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

#endif /* _ASM_GENERIC_HUGETLB_H */

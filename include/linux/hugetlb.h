/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HUGETLB_H
#define _LINUX_HUGETLB_H

#include <linux/mm_types.h>
#include <linux/mmdebug.h>
#include <linux/fs.h>
#if 0
#include <linux/hugetlb_inline.h>
#include <linux/cgroup.h>
#include <linux/userfaultfd_k.h>
#endif
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/pgtable.h>
#include <linux/gfp.h>

#include <asm/hugetlb.h>

#ifndef arch_make_huge_pte
static inline pte_t arch_make_huge_pte(pte_t entry, unsigned int shift,
                                       vm_flags_t flags)
{
    return pte_mkhuge(entry);
}
#endif

static inline void hugetlb_count_init(struct mm_struct *mm)
{
    atomic_long_set(&mm->hugetlb_usage, 0);
}

#endif /* _LINUX_HUGETLB_H */

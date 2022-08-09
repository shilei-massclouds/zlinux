/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HUGETLB_INLINE_H
#define _LINUX_HUGETLB_INLINE_H

#include <linux/mm.h>

static inline bool is_vm_hugetlb_page(struct vm_area_struct *vma)
{
    return !!(vma->vm_flags & VM_HUGETLB);
}

#endif /* _LINUX_HUGETLB_INLINE_H */

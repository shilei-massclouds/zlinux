/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HUGETLB_H
#define _LINUX_HUGETLB_H

#include <linux/mm_types.h>
#include <linux/mmdebug.h>
#include <linux/fs.h>
#include <linux/hugetlb_inline.h>
#if 0
#include <linux/cgroup.h>
#include <linux/userfaultfd_k.h>
#endif
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/pgtable.h>
#include <linux/gfp.h>

#include <asm/hugetlb.h>

typedef struct { unsigned long pd; } hugepd_t;

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

struct page *
follow_huge_addr(struct mm_struct *mm, unsigned long address, int write);

vm_fault_t
hugetlb_fault(struct mm_struct *mm, struct vm_area_struct *vma,
              unsigned long address, unsigned int flags);

struct page *follow_huge_pd(struct vm_area_struct *vma,
                            unsigned long address, hugepd_t hpd,
                            int flags, int pdshift);
struct page *follow_huge_pmd(struct mm_struct *mm, unsigned long address,
                             pmd_t *pmd, int flags);
struct page *follow_huge_pud(struct mm_struct *mm, unsigned long address,
                             pud_t *pud, int flags);
struct page *follow_huge_pgd(struct mm_struct *mm, unsigned long address,
                             pgd_t *pgd, int flags);

int pmd_huge(pmd_t pmd);
int pud_huge(pud_t pud);

extern const struct file_operations hugetlbfs_file_operations;

static inline bool is_file_hugepages(struct file *file)
{
    if (file->f_op == &hugetlbfs_file_operations)
        return true;

    return is_file_shm_hugepages(file);
}

#endif /* _LINUX_HUGETLB_H */

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

#define HSTATE_NAME_LEN 32
/* Defines one hugetlb page size */
struct hstate {
    struct mutex resize_lock;
    int next_nid_to_alloc;
    int next_nid_to_free;
    unsigned int order;
    unsigned int demote_order;
    unsigned long mask;
    unsigned long max_huge_pages;
    unsigned long nr_huge_pages;
    unsigned long free_huge_pages;
    unsigned long resv_huge_pages;
    unsigned long surplus_huge_pages;
    unsigned long nr_overcommit_huge_pages;
    struct list_head hugepage_activelist;
    struct list_head hugepage_freelists[MAX_NUMNODES];
    unsigned int max_huge_pages_node[MAX_NUMNODES];
    unsigned int nr_huge_pages_node[MAX_NUMNODES];
    unsigned int free_huge_pages_node[MAX_NUMNODES];
    unsigned int surplus_huge_pages_node[MAX_NUMNODES];
    char name[HSTATE_NAME_LEN];
};

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

void free_huge_page(struct page *page);

static inline struct hstate *hstate_inode(struct inode *i)
{
#if 0
    return HUGETLBFS_SB(i->i_sb)->hstate;
#endif
    panic("%s: END!\n", __func__);
}

static inline struct hstate *hstate_file(struct file *f)
{
    return hstate_inode(file_inode(f));
}

static inline unsigned long huge_page_size(struct hstate *h)
{
    return (unsigned long)PAGE_SIZE << h->order;
}

#endif /* _LINUX_HUGETLB_H */

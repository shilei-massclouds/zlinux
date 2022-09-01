/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_KSM_H
#define __LINUX_KSM_H
/*
 * Memory merging support.
 *
 * This code enables dynamic sharing of identical pages found in different
 * memory areas, even if they are not shared by fork().
 */

#include <linux/bitops.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/sched.h>
#include <linux/sched/coredump.h>

struct stable_node;
struct mem_cgroup;

static inline int ksm_fork(struct mm_struct *mm, struct mm_struct *oldmm)
{
    return 0;
}

static inline void ksm_exit(struct mm_struct *mm)
{
}

static inline
int ksm_madvise(struct vm_area_struct *vma, unsigned long start,
                unsigned long end, int advice, unsigned long *vm_flags)
{
    return 0;
}

static inline
struct page *ksm_might_need_to_copy(struct page *page,
                                    struct vm_area_struct *vma,
                                    unsigned long address)
{
    return page;
}

static inline
void rmap_walk_ksm(struct folio *folio, const struct rmap_walk_control *rwc)
{
}

static inline void folio_migrate_ksm(struct folio *newfolio, struct folio *old)
{
}

#endif /* __LINUX_KSM_H */

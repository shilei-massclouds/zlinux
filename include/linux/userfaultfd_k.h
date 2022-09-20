/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  include/linux/userfaultfd_k.h
 *
 *  Copyright (C) 2015  Red Hat, Inc.
 *
 */

#ifndef _LINUX_USERFAULTFD_K_H
#define _LINUX_USERFAULTFD_K_H

/* mm helpers */
static inline
vm_fault_t handle_userfault(struct vm_fault *vmf, unsigned long reason)
{
    return VM_FAULT_SIGBUS;
}

static inline
bool is_mergeable_vm_userfaultfd_ctx(struct vm_area_struct *vma,
                                     struct vm_userfaultfd_ctx vm_ctx)
{
    return true;
}

static inline bool userfaultfd_missing(struct vm_area_struct *vma)
{
    return false;
}

static inline bool userfaultfd_wp(struct vm_area_struct *vma)
{
    return false;
}

static inline bool userfaultfd_minor(struct vm_area_struct *vma)
{
    return false;
}

static inline
bool userfaultfd_pte_wp(struct vm_area_struct *vma, pte_t pte)
{
    return false;
}

static inline
bool userfaultfd_huge_pmd_wp(struct vm_area_struct *vma, pmd_t pmd)
{
    return false;
}


static inline bool userfaultfd_armed(struct vm_area_struct *vma)
{
    return false;
}

static inline int dup_userfaultfd(struct vm_area_struct *vma,
                  struct list_head *l)
{
    return 0;
}

static inline void dup_userfaultfd_complete(struct list_head *l)
{
}

static inline
void mremap_userfaultfd_prep(struct vm_area_struct *vma,
                             struct vm_userfaultfd_ctx *ctx)
{
}

static inline
void mremap_userfaultfd_complete(struct vm_userfaultfd_ctx *ctx,
                                 unsigned long from,
                                 unsigned long to,
                                 unsigned long len)
{
}

static inline
bool userfaultfd_remove(struct vm_area_struct *vma,
                        unsigned long start, unsigned long end)
{
    return true;
}

static inline
int userfaultfd_unmap_prep(struct vm_area_struct *vma,
                           unsigned long start, unsigned long end,
                           struct list_head *uf)
{
    return 0;
}

static inline
void userfaultfd_unmap_complete(struct mm_struct *mm,
                                struct list_head *uf)
{
}

#endif /* _LINUX_USERFAULTFD_K_H */

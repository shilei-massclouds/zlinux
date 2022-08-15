// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/interval_tree.c - interval tree for mapping->i_mmap
 *
 * Copyright (C) 2012, Michel Lespinasse <walken@google.com>
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/rmap.h>
#include <linux/interval_tree_generic.h>

static inline unsigned long vma_start_pgoff(struct vm_area_struct *v)
{
    return v->vm_pgoff;
}

static inline unsigned long vma_last_pgoff(struct vm_area_struct *v)
{
    return v->vm_pgoff + vma_pages(v) - 1;
}

INTERVAL_TREE_DEFINE(struct vm_area_struct, shared.rb,
                     unsigned long, shared.rb_subtree_last,
                     vma_start_pgoff, vma_last_pgoff, /* empty */,
                     vma_interval_tree)

static inline unsigned long avc_start_pgoff(struct anon_vma_chain *avc)
{
    return vma_start_pgoff(avc->vma);
}

static inline unsigned long avc_last_pgoff(struct anon_vma_chain *avc)
{
    return vma_last_pgoff(avc->vma);
}

INTERVAL_TREE_DEFINE(struct anon_vma_chain, rb, unsigned long, rb_subtree_last,
                     avc_start_pgoff, avc_last_pgoff,
                     static inline, __anon_vma_interval_tree)

void anon_vma_interval_tree_insert(struct anon_vma_chain *node,
                                   struct rb_root_cached *root)
{
    __anon_vma_interval_tree_insert(node, root);
}

void anon_vma_interval_tree_remove(struct anon_vma_chain *node,
                                   struct rb_root_cached *root)
{
    __anon_vma_interval_tree_remove(node, root);
}

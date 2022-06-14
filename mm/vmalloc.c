// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 1993  Linus Torvalds
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  SMP-safe vmalloc/vfree/ioremap, Tigran Aivazian <tigran@veritas.com>, May 2000
 *  Major rework to support vmap/vunmap, Christoph Hellwig, SGI, August 2002
 *  Numa awareness, Christoph Lameter, SGI, June 2005
 *  Improving global KVA allocator, Uladzislau Rezki, Sony, May 2019
 */
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/set_memory.h>
#include <linux/debugobjects.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/rbtree.h>
#include <linux/xarray.h>
#include <linux/io.h>
#include <linux/rcupdate.h>
#include <linux/pfn.h>
#include <linux/kmemleak.h>
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/memcontrol.h>
#include <linux/llist.h>
#include <linux/bitops.h>
#include <linux/rbtree_augmented.h>
#include <linux/overflow.h>
#include <linux/pgtable.h>
#include <linux/uaccess.h>
#include <linux/hugetlb.h>
#include <linux/sched/mm.h>
#include <asm/tlbflush.h>
#include <asm/shmparam.h>

#include "internal.h"
#include "pgalloc-track.h"

static struct vmap_area *__find_vmap_area(unsigned long addr)
{
    struct rb_node *n = vmap_area_root.rb_node;

    addr = (unsigned long)kasan_reset_tag((void *)addr);

    while (n) {
        struct vmap_area *va;

        va = rb_entry(n, struct vmap_area, rb_node);
        if (addr < va->va_start)
            n = n->rb_left;
        else if (addr >= va->va_end)
            n = n->rb_right;
        else
            return va;
    }

    return NULL;
}

static struct vmap_area *find_vmap_area(unsigned long addr)
{
    struct vmap_area *va;

    spin_lock(&vmap_area_lock);
    va = __find_vmap_area(addr);
    spin_unlock(&vmap_area_lock);

    return va;
}

/**
 * find_vm_area - find a continuous kernel virtual area
 * @addr:     base address
 *
 * Search for the kernel VM area starting at @addr, and return it.
 * It is up to the caller to do all required locking to keep the returned
 * pointer valid.
 *
 * Return: the area descriptor on success or %NULL on failure.
 */
struct vm_struct *find_vm_area(const void *addr)
{
    struct vmap_area *va;

    va = find_vmap_area((unsigned long)addr);
    if (!va)
        return NULL;

    return va->vm;
}

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VMALLOC_H
#define _LINUX_VMALLOC_H

#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/list.h>
//#include <linux/llist.h>
#include <asm/page.h>       /* pgprot_t */
#include <linux/rbtree.h>
#include <linux/overflow.h>

//#include <asm/vmalloc.h>

/* bits in flags of vmalloc's vm_struct below */
#define VM_IOREMAP          0x00000001  /* ioremap() and friends */
#define VM_ALLOC            0x00000002  /* vmalloc() */
#define VM_UNINITIALIZED    0x00000020  /* vm_struct is not fully initialized */
#define VM_NO_GUARD         0x00000040  /* ***DANGEROUS*** don't add guard page */

#define VMALLOC_TOTAL (VMALLOC_END - VMALLOC_START)

/*
 * Maximum alignment for ioremap() regions.
 * Can be overridden by arch-specific value.
 */
#ifndef IOREMAP_MAX_ORDER
#define IOREMAP_MAX_ORDER   (7 + PAGE_SHIFT)    /* 128 pages */
#endif

struct vm_struct {
    struct vm_struct    *next;
    void                *addr;
    unsigned long       size;
    unsigned long       flags;
    struct page         **pages;
    unsigned int        nr_pages;
    phys_addr_t         phys_addr;
    const void          *caller;
};

struct vmap_area {
    unsigned long va_start;
    unsigned long va_end;

    struct rb_node rb_node;         /* address sorted rbtree */
    struct list_head list;          /* address sorted list */

    /*
     * The following two variables can be packed, because
     * a vmap_area object can be either:
     *    1) in "free" tree (root is free_vmap_area_root)
     *    2) or "busy" tree (root is vmap_area_root)
     */
    union {
        unsigned long subtree_max_size; /* in "free" tree */
        struct vm_struct *vm;           /* in "busy" tree */
    };
};

extern void __init vmalloc_init(void);

extern void *
__vmalloc_node_range(unsigned long size, unsigned long align,
                     unsigned long start, unsigned long end, gfp_t gfp_mask,
                     pgprot_t prot, unsigned long vm_flags, int node,
                     const void *caller) __alloc_size(1);

void *
__vmalloc_node(unsigned long size, unsigned long align, gfp_t gfp_mask,
               int node, const void *caller) __alloc_size(1);

void free_vm_area(struct vm_struct *area);

/*
 *  Lowlevel-APIs (not for driver use!)
 */

static inline size_t get_vm_area_size(const struct vm_struct *area)
{
    if (!(area->flags & VM_NO_GUARD))
        /* return actual size without guard page */
        return area->size - PAGE_SIZE;
    else
        return area->size;

}

#endif /* _LINUX_VMALLOC_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SLAB_DEF_H
#define _LINUX_SLAB_DEF_H

//#include <linux/reciprocal_div.h>
#include <linux/numa.h>

/*
 * Definitions unique to the original Linux SLAB allocator.
 */

struct kmem_cache {
    struct array_cache __percpu *cpu_cache;

/* 1) Cache tunables. Protected by slab_mutex */
    unsigned int batchcount;
    unsigned int limit;
    unsigned int shared;

    unsigned int size;
    //struct reciprocal_value reciprocal_buffer_size;
/* 2) touched by every alloc & free from the backend */

    slab_flags_t flags;     /* constant flags */
    unsigned int num;       /* # of objs per slab */

/* 3) cache_grow/shrink */
    /* order of pgs per slab (2^n) */
    unsigned int gfporder;

    /* force GFP flags, e.g. GFP_DMA */
    gfp_t allocflags;

    size_t colour;          /* cache colouring range */
    unsigned int colour_off;    /* colour offset */
    struct kmem_cache *freelist_cache;
    unsigned int freelist_size;

    /* constructor func */
    void (*ctor)(void *obj);

/* 4) cache creation/removal */
    const char *name;
    struct list_head list;
    int refcount;
    int object_size;
    int align;

/* 5) statistics */
    unsigned int useroffset;    /* Usercopy region offset */
    unsigned int usersize;      /* Usercopy region size */

    struct kmem_cache_node *node[MAX_NUMNODES];
};

#endif  /* _LINUX_SLAB_DEF_H */

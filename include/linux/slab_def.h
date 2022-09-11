/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SLAB_DEF_H
#define _LINUX_SLAB_DEF_H

#include <linux/reciprocal_div.h>
#include <linux/numa.h>

/*
 * Definitions unique to the original Linux SLAB allocator.
 */

/*
 * The slab lists for all objects.
 */
struct kmem_cache_node {
    spinlock_t list_lock;

    struct list_head slabs_partial; /* partial list first, better asm code */
    struct list_head slabs_full;
    struct list_head slabs_free;
    unsigned long total_slabs;  /* length of all slab lists */
    unsigned long free_slabs;   /* length of free slab list only */
    unsigned long free_objects;
    unsigned int free_limit;
    unsigned int colour_next;   /* Per-node cache coloring */
    struct array_cache *shared; /* shared per node */
    struct alien_cache **alien; /* on other nodes */
    unsigned long next_reap;    /* updated without locking */
    int free_touched;       /* updated without locking */
};

struct kmem_cache {
    struct array_cache __percpu *cpu_cache;

/* 1) Cache tunables. Protected by slab_mutex */
    unsigned int batchcount;
    unsigned int limit;
    unsigned int shared;

    unsigned int size;
    struct reciprocal_value reciprocal_buffer_size;
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

/*
 * We want to avoid an expensive divide : (offset / cache->size)
 *   Using the fact that size is a constant for a particular cache,
 *   we can replace (offset / cache->size) by
 *   reciprocal_divide(offset, cache->reciprocal_buffer_size)
 */
static inline
unsigned int obj_to_index(const struct kmem_cache *cache,
                          const struct slab *slab, void *obj)
{
    u32 offset = (obj - slab->s_mem);
    return reciprocal_divide(offset, cache->reciprocal_buffer_size);
}

#endif  /* _LINUX_SLAB_DEF_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MM_SLAB_H
#define MM_SLAB_H
/*
 * Internal slab definitions
 */

#include <linux/slab_def.h>
#include <linux/string.h>
#include <linux/memcontrol.h>
#include <linux/jump_label.h>

/*
#include <linux/fault-inject.h>
#include <linux/kasan.h>
#include <linux/kmemleak.h>
#include <linux/random.h>
#include <linux/sched/mm.h>
*/

/*
 * State of the slab allocator.
 *
 * This is used to describe the states of the allocator during bootup.
 * Allocators use this to gradually bootstrap themselves. Most allocators
 * have the problem that the structures used for managing slab caches are
 * allocated from slab caches themselves.
 */
enum slab_state {
    DOWN,           /* No slab functionality yet */
    PARTIAL,        /* SLUB: kmem_cache_node available */
    PARTIAL_NODE,   /* SLAB: kmalloc size for node struct available */
    UP,             /* Slab caches usable but not all extras yet */
    FULL            /* Everything is working */
};

extern enum slab_state slab_state;

/* The list of all slab caches on the system */
extern struct list_head slab_caches;

/* The slab cache that manages slab cache information */
extern struct kmem_cache *kmem_cache;

static inline struct kmem_cache *
slab_pre_alloc_hook(struct kmem_cache *s, struct obj_cgroup **objcgp,
                    size_t size, gfp_t flags)
{
    return s;
}

static inline void
slab_post_alloc_hook(struct kmem_cache *s,
                     struct obj_cgroup *objcg, gfp_t flags,
                     size_t size, void **p, bool init)
{
    size_t i;

    flags &= gfp_allowed_mask;

    /*
     * As memory initialization might be integrated into KASAN,
     * kasan_slab_alloc and initialization memset must be
     * kept together to avoid discrepancies in behavior.
     *
     * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
     */
    for (i = 0; i < size; i++) {
        if (p[i] && init)
            memset(p[i], 0, s->object_size);
    }
}

static inline bool slab_want_init_on_alloc(gfp_t flags, struct kmem_cache *c)
{
    if (static_branch_maybe(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, &init_on_alloc)) {
        if (c->ctor)
            return false;
        if (c->flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON))
            return flags & __GFP_ZERO;
        return true;
    }
    return flags & __GFP_ZERO;
}

static inline bool slab_want_init_on_free(struct kmem_cache *c)
{
    return false;
}

static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int node)
{
    return s->node[node];
}

static inline enum node_stat_item cache_vmstat_idx(struct kmem_cache *s)
{
    return (s->flags & SLAB_RECLAIM_ACCOUNT) ?
        NR_SLAB_RECLAIMABLE_B : NR_SLAB_UNRECLAIMABLE_B;
}

static __always_inline void
account_slab_page(struct page *page, int order,
                  struct kmem_cache *s, gfp_t gfp)
{
    mod_node_page_state(page_pgdat(page),
                        cache_vmstat_idx(s), PAGE_SIZE << order);
}

static __always_inline void
unaccount_slab_page(struct page *page, int order, struct kmem_cache *s)
{
    mod_node_page_state(page_pgdat(page), cache_vmstat_idx(s),
                        -(PAGE_SIZE << order));
}

gfp_t kmalloc_fix_flags(gfp_t flags);

extern void create_boot_cache(struct kmem_cache *, const char *name,
                              unsigned int size, slab_flags_t flags,
                              unsigned int useroffset, unsigned int usersize);

/* Functions provided by the slab allocators */
int __kmem_cache_create(struct kmem_cache *, slab_flags_t flags);

struct kmem_cache *kmalloc_slab(size_t, gfp_t);

/*
 * Iterator over all nodes. The body will be executed for each node that has
 * a kmem_cache_node structure allocated (which is true for all online nodes)
 */
#define for_each_kmem_cache_node(__s, __node, __n) \
    for (__node = 0; __node < nr_node_ids; __node++) \
         if ((__n = get_node(__s, __node)))

#endif /* MM_SLAB_H */

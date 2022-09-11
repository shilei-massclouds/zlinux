/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MM_SLAB_H
#define MM_SLAB_H
/*
 * Internal slab definitions
 */

/* Reuses the bits in struct page */
struct slab {
    unsigned long __page_flags;

    union {
        struct list_head slab_list;
        struct rcu_head rcu_head;
    };
    struct kmem_cache *slab_cache;
    void *freelist; /* array of free object indexes */
    void *s_mem;    /* first object */
    unsigned int active;

    atomic_t __page_refcount;
};

#include <linux/slab_def.h>
#include <linux/string.h>
#include <linux/memcontrol.h>
#include <linux/jump_label.h>

/*
#include <linux/fault-inject.h>
#include <linux/random.h>
#include <linux/sched/mm.h>
*/

/* Legal flag mask for kmem_cache_create(), for various configurations */
#define SLAB_CORE_FLAGS (SLAB_HWCACHE_ALIGN | SLAB_CACHE_DMA | \
                         SLAB_CACHE_DMA32 | SLAB_PANIC | \
                         SLAB_TYPESAFE_BY_RCU | SLAB_DEBUG_OBJECTS )

#define SLAB_CACHE_FLAGS (SLAB_MEM_SPREAD | SLAB_NOLEAKTRACE | \
                          SLAB_RECLAIM_ACCOUNT | SLAB_TEMPORARY | \
                          SLAB_ACCOUNT)

#define SLAB_DEBUG_FLAGS (0)

/* Common flags available with current configuration */
#define CACHE_CREATE_MASK \
    (SLAB_CORE_FLAGS | SLAB_DEBUG_FLAGS | SLAB_CACHE_FLAGS)

/* Common flags permitted for kmem_cache_create */
#define SLAB_FLAGS_PERMITTED (SLAB_CORE_FLAGS | \
                              SLAB_RED_ZONE | \
                              SLAB_POISON | \
                              SLAB_STORE_USER | \
                              SLAB_TRACE | \
                              SLAB_CONSISTENCY_CHECKS | \
                              SLAB_MEM_SPREAD | \
                              SLAB_NOLEAKTRACE | \
                              SLAB_RECLAIM_ACCOUNT | \
                              SLAB_TEMPORARY | \
                              SLAB_ACCOUNT)

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

/* A table of kmalloc cache names and sizes */
extern const struct kmalloc_info_struct {
    const char *name[NR_KMALLOC_TYPES];
    unsigned int size;
} kmalloc_info[];

extern enum slab_state slab_state;

/* The list of all slab caches on the system */
extern struct list_head slab_caches;

/* The slab cache that manages slab cache information */
extern struct kmem_cache *kmem_cache;

/* Kmalloc array related functions */
void setup_kmalloc_cache_index_table(void);

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

void create_kmalloc_caches(slab_flags_t);

struct kmem_cache *
create_kmalloc_cache(const char *name, unsigned int size, slab_flags_t flags,
                     unsigned int useroffset, unsigned int usersize);

extern struct mutex slab_mutex;

struct kmem_cache *
__kmem_cache_alias(const char *name, unsigned int size, unsigned int align,
                   slab_flags_t flags, void (*ctor)(void *));

slab_flags_t kmem_cache_flags(unsigned int object_size,
                              slab_flags_t flags, const char *name);

int slab_unmergeable(struct kmem_cache *s);

struct kmem_cache *
find_mergeable(unsigned size, unsigned align, slab_flags_t flags,
               const char *name, void (*ctor)(void *));

/**
 * folio_slab - Converts from folio to slab.
 * @folio: The folio.
 *
 * Currently struct slab is a different representation of a folio where
 * folio_test_slab() is true.
 *
 * Return: The slab which contains this folio.
 */
#define folio_slab(folio)   (_Generic((folio),          \
    const struct folio *:   (const struct slab *)(folio),       \
    struct folio *:     (struct slab *)(folio)))

static inline struct slab *virt_to_slab(const void *addr)
{
    struct folio *folio = virt_to_folio(addr);

    if (!folio_test_slab(folio))
        return NULL;

    return folio_slab(folio);
}

static inline struct kmem_cache *virt_to_cache(const void *obj)
{
    struct slab *slab;

    slab = virt_to_slab(obj);
    if (WARN_ONCE(!slab, "%s: Object is not a Slab page!\n", __func__))
        return NULL;
    return slab->slab_cache;
}

/**
 * slab_folio - The folio allocated for a slab
 * @slab: The slab.
 *
 * Slabs are allocated as folios that contain the individual objects and are
 * using some fields in the first struct page of the folio - those fields are
 * now accessed by struct slab. It is occasionally necessary to convert back to
 * a folio in order to communicate with the rest of the mm.  Please use this
 * helper function instead of casting yourself, as the implementation may change
 * in the future.
 */
#define slab_folio(s)       (_Generic((s),              \
    const struct slab *:    (const struct folio *)s,        \
    struct slab *:      (struct folio *)s))

static inline void *slab_address(const struct slab *slab)
{
    return folio_address(slab_folio(slab));
}

static inline pg_data_t *slab_pgdat(const struct slab *slab)
{
    return folio_pgdat(slab_folio(slab));
}

static __always_inline
void unaccount_slab(struct slab *slab, int order, struct kmem_cache *s)
{
    mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
                        -(PAGE_SIZE << order));
}

static inline void __slab_clear_pfmemalloc(struct slab *slab)
{
    __folio_clear_active(slab_folio(slab));
}

static __always_inline
void account_slab(struct slab *slab, int order,
                  struct kmem_cache *s, gfp_t gfp)
{
    mod_node_page_state(slab_pgdat(slab), cache_vmstat_idx(s),
                        PAGE_SIZE << order);
}

static inline int slab_nid(const struct slab *slab)
{
    return folio_nid(slab_folio(slab));
}

#endif /* MM_SLAB_H */

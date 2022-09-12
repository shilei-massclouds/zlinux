// SPDX-License-Identifier: GPL-2.0

#include    <linux/slab.h>
#include    <linux/mm.h>
#include    <linux/poison.h>
#include    <linux/swap.h>
#include    <linux/cache.h>
//#include    <linux/interrupt.h>
#include    <linux/init.h>
#include    <linux/compiler.h>
//#include    <linux/cpuset.h>
/*
#include    <linux/proc_fs.h>
#include    <linux/seq_file.h>
#include    <linux/notifier.h>
#include    <linux/kallsyms.h>
*/
#include    <linux/cpu.h>
//#include    <linux/sysctl.h>
#include    <linux/module.h>
#include    <linux/string.h>
#include    <linux/nodemask.h>
#include    <linux/rcupdate.h>
#include    <linux/uaccess.h>
#include    <linux/mutex.h>
/*
#include    <linux/mempolicy.h>
#include    <linux/fault-inject.h>
#include    <linux/rtmutex.h>
#include    <linux/debugobjects.h>
#include    <linux/sched/task_stack.h>
#include    <linux/memory.h>
*/
#include    <linux/reciprocal_div.h>
#include    <linux/prefetch.h>
#include    <linux/jiffies.h>

/*
#include    <net/sock.h>

#include    <asm/cacheflush.h>
*/
#include    <asm/tlbflush.h>
#include    <asm/page.h>

#include    "internal.h"

#include    "slab.h"

#ifndef ARCH_KMALLOC_FLAGS
#define ARCH_KMALLOC_FLAGS SLAB_HWCACHE_ALIGN
#endif

/* Shouldn't this be in a header file somewhere? */
#define BYTES_PER_WORD  sizeof(void *)
#define REDZONE_ALIGN   max(BYTES_PER_WORD, __alignof__(unsigned long long))

#define BATCHREFILL_LIMIT   16

#define REAPTIMEOUT_NODE    (4*HZ)

#define CFLGS_OBJFREELIST_SLAB  ((slab_flags_t __force)0x40000000U)
#define CFLGS_OFF_SLAB          ((slab_flags_t __force)0x80000000U)

#define OBJFREELIST_SLAB(x)     ((x)->flags & CFLGS_OBJFREELIST_SLAB)
#define OFF_SLAB(x)             ((x)->flags & CFLGS_OFF_SLAB)

#define FREELIST_BYTE_INDEX \
    (((PAGE_SIZE >> BITS_PER_BYTE) <= SLAB_OBJ_MIN_SIZE) ? 1 : 0)

#if FREELIST_BYTE_INDEX
typedef unsigned char freelist_idx_t;
#else
typedef unsigned short freelist_idx_t;
#endif

#define SLAB_OBJ_MAX_NUM ((1 << sizeof(freelist_idx_t) * BITS_PER_BYTE) - 1)

#define obj_offset(x) 0

/*
 * Do not go above this order unless 0 objects fit into the slab or
 * overridden on the command line.
 */
#define SLAB_MAX_ORDER_HI   1
#define SLAB_MAX_ORDER_LO   0
static int slab_max_order = SLAB_MAX_ORDER_LO;
static bool slab_max_order_set __initdata;

static int slab_early_init = 1;

#define INDEX_NODE kmalloc_index(sizeof(struct kmem_cache_node))

#define BOOT_CPUCACHE_ENTRIES   1
/* internal cache of cache description objs */
static struct kmem_cache kmem_cache_boot = {
    .batchcount = 1,
    .limit = BOOT_CPUCACHE_ENTRIES,
    .shared = 1,
    .size = sizeof(struct kmem_cache),
    .name = "kmem_cache",
};

static int use_alien_caches __read_mostly = 1;

/*
 * Need this for bootstrapping a per node allocator.
 */
#define NUM_INIT_LISTS (2 * MAX_NUMNODES)
static struct kmem_cache_node __initdata init_kmem_cache_node[NUM_INIT_LISTS];
#define CACHE_CACHE 0
#define SIZE_NODE (MAX_NUMNODES)

/*
 * struct array_cache
 *
 * Purpose:
 * - LIFO ordering, to hand out cache-warm objects from _alloc
 * - reduce the number of linked list operations
 * - reduce spinlock operations
 *
 * The limit is stored in the per-cpu structure to reduce the data cache
 * footprint.
 *
 */
struct array_cache {
    unsigned int avail;
    unsigned int limit;
    unsigned int batchcount;
    unsigned int touched;
    void *entry[];  /*
                     * Must have this definition in here for the proper
                     * alignment of array_cache. Also simplifies accessing
                     * the entries.
                     */
};

static inline struct array_cache *cpu_cache_get(struct kmem_cache *cachep)
{
    return this_cpu_ptr(cachep->cpu_cache);
}

/*
 * Transfer objects in one arraycache to another.
 * Locking must be handled by the caller.
 *
 * Return the number of entries transferred.
 */
static int transfer_objects(struct array_cache *to, struct array_cache *from,
                            unsigned int max)
{
    /* Figure out how many entries to transfer */
    int nr = min3(from->avail, max, to->limit - to->avail);
    if (!nr)
        return 0;

    memcpy(to->entry + to->avail, from->entry + from->avail - nr,
           sizeof(void *) * nr);

    from->avail -= nr;
    to->avail += nr;
    return nr;
}

static struct page *
get_first_slab(struct kmem_cache_node *n, bool pfmemalloc)
{
    struct slab *slab;

    assert_spin_locked(&n->list_lock);
    slab = list_first_entry_or_null(&n->slabs_partial, struct slab,
                                    slab_list);
    if (!slab) {
        n->free_touched = 1;
        slab = list_first_entry_or_null(&n->slabs_free, struct slab,
                                        slab_list);
        if (slab)
            n->free_slabs--;
    }

#if 0
    if (sk_memalloc_socks())
        slab = get_valid_first_slab(n, slab, pfmemalloc);
#endif

    return slab;
}

static inline
freelist_idx_t get_free_obj(struct slab *slab, unsigned int idx)
{
    return ((freelist_idx_t *) slab->freelist)[idx];
}

static inline void set_free_obj(struct slab *slab,
                                unsigned int idx, freelist_idx_t val)
{
    ((freelist_idx_t *)(slab->freelist))[idx] = val;
}

static inline void *
index_to_obj(struct kmem_cache *cache,
             const struct slab *slab, unsigned int idx)
{
    return slab->s_mem + cache->size * idx;
}

static void *slab_get_obj(struct kmem_cache *cachep, struct slab *slab)
{
    void *objp;

    objp = index_to_obj(cachep, slab, get_free_obj(slab, slab->active));
    slab->active++;

    return objp;
}

/*
 * Slab list should be fixed up by fixup_slab_list() for existing slab
 * or cache_grow_end() for new slab
 */
static __always_inline int
alloc_block(struct kmem_cache *cachep, struct array_cache *ac,
            struct slab *slab, int batchcount)
{
    /*
     * There must be at least one object available for allocation.
     */
    BUG_ON(slab->active >= cachep->num);

    while (slab->active < cachep->num && batchcount--)
        ac->entry[ac->avail++] = slab_get_obj(cachep, slab);

    return batchcount;
}

static inline void
fixup_slab_list(struct kmem_cache *cachep, struct kmem_cache_node *n,
                struct slab *slab, void **list)
{
    /* move slabp to correct slabp list: */
    list_del(&slab->slab_list);
    if (slab->active == cachep->num) {
        list_add(&slab->slab_list, &n->slabs_full);
        if (OBJFREELIST_SLAB(cachep))
            slab->freelist = NULL;
    } else
        list_add(&slab->slab_list, &n->slabs_partial);
}

static inline gfp_t gfp_exact_node(gfp_t flags)
{
    return flags & ~__GFP_NOFAIL;
}

static noinline void
slab_out_of_memory(struct kmem_cache *cachep, gfp_t gfpflags,
                   int nodeid)
{
}

/*
 * Interface to system's page allocator. No need to hold the
 * kmem_cache_node ->list_lock.
 *
 * If we requested dmaable memory, we will get it. Even if we
 * did not request dmaable memory, we might get it, but that
 * would be relatively rare and ignorable.
 */
static struct slab *
kmem_getpages(struct kmem_cache *cachep, gfp_t flags, int nodeid)
{
    struct folio *folio;
    struct slab *slab;

    flags |= cachep->allocflags;

    folio = (struct folio *) __alloc_pages_node(nodeid, flags,
                                                cachep->gfporder);
    if (!folio) {
        slab_out_of_memory(cachep, flags, nodeid);
        return NULL;
    }

    slab = folio_slab(folio);

    account_slab(slab, cachep->gfporder, cachep, flags);
    __folio_set_slab(folio);
#if 0
    /* Record if ALLOC_NO_WATERMARKS was set when allocating the slab */
    if (sk_memalloc_socks() && page_is_pfmemalloc(folio_page(folio, 0)))
        slab_set_pfmemalloc(slab);
#endif

    return slab;
}

/*
 * Get the memory for a slab management obj.
 *
 * For a slab cache when the slab descriptor is off-slab, the
 * slab descriptor can't come from the same cache which is being created,
 * Because if it is the case, that means we defer the creation of
 * the kmalloc_{dma,}_cache of size sizeof(slab descriptor) to this point.
 * And we eventually call down to __kmem_cache_create(), which
 * in turn looks up in the kmalloc_{dma,}_caches for the desired-size one.
 * This is a "chicken-and-egg" problem.
 *
 * So the off-slab slab descriptor shall come from the kmalloc_{dma,}_caches,
 * which are all initialized during kmem_cache_init().
 */
static void *alloc_slabmgmt(struct kmem_cache *cachep,
                            struct slab *slab, int colour_off,
                            gfp_t local_flags, int nodeid)
{
    void *freelist;
    void *addr = slab_address(slab);

    slab->s_mem = addr + colour_off;
    slab->active = 0;

    if (OBJFREELIST_SLAB(cachep))
        freelist = NULL;
    else if (OFF_SLAB(cachep)) {
        /* Slab management obj is off-slab. */
        freelist = kmem_cache_alloc_node(cachep->freelist_cache,
                                         local_flags, nodeid);
    } else {
        /* We will use last bytes at the slab for freelist */
        freelist = addr + (PAGE_SIZE << cachep->gfporder) -
            cachep->freelist_size;
    }

    return freelist;
}

/*
 * Interface to system's page release.
 */
static void kmem_freepages(struct kmem_cache *cachep, struct slab *slab)
{
    int order = cachep->gfporder;
    struct folio *folio = slab_folio(slab);

    BUG_ON(!folio_test_slab(folio));
    __slab_clear_pfmemalloc(slab);
    __folio_clear_slab(folio);
    page_mapcount_reset(folio_page(folio, 0));
    folio->mapping = NULL;

    if (current->reclaim_state)
        current->reclaim_state->reclaimed_slab += 1 << order;
    unaccount_slab(slab, order, cachep);
    __free_pages(folio_page(folio, 0), order);
}

static inline bool
shuffle_freelist(struct kmem_cache *cachep, struct page *page)
{
    return false;
}

static void cache_init_objs(struct kmem_cache *cachep,
                            struct slab *slab)
{
    int i;
    void *objp;
    bool shuffled;

    /* Try to randomize the freelist if enabled */
    shuffled = shuffle_freelist(cachep, slab);

    if (!shuffled && OBJFREELIST_SLAB(cachep)) {
        slab->freelist = index_to_obj(cachep, slab, cachep->num - 1) +
            obj_offset(cachep);
    }

    for (i = 0; i < cachep->num; i++) {
        objp = index_to_obj(cachep, slab, i);

        /* constructor could break poison info */
        if (cachep->ctor)
            cachep->ctor(objp);

        if (!shuffled)
            set_free_obj(slab, i, i);
    }
}

/*
 * Grow (by 1) the number of slabs within a cache.  This is called by
 * kmem_cache_alloc() when there are no active objs left in a cache.
 */
static struct page *
cache_grow_begin(struct kmem_cache *cachep, gfp_t flags, int nodeid)
{
    void *freelist;
    size_t offset;
    gfp_t local_flags;
    int slab_node;
    struct kmem_cache_node *n;
    struct slab *slab;

    /*
     * Be lazy and only check for valid flags here,  keeping it out of the
     * critical path in kmem_cache_alloc().
     */
    if (unlikely(flags & GFP_SLAB_BUG_MASK))
        flags = kmalloc_fix_flags(flags);

    WARN_ON_ONCE(cachep->ctor && (flags & __GFP_ZERO));
    local_flags = flags & (GFP_CONSTRAINT_MASK|GFP_RECLAIM_MASK);

    if (gfpflags_allow_blocking(local_flags))
        local_irq_enable();

    /*
     * Get mem for the objs.  Attempt to allocate a physical page from
     * 'nodeid'.
     */
    slab = kmem_getpages(cachep, local_flags, nodeid);
    if (!slab)
        goto failed;

    slab_node = slab_nid(slab);
    n = get_node(cachep, slab_node);

    /* Get colour for the slab, and cal the next value. */
    n->colour_next++;
    if (n->colour_next >= cachep->colour)
        n->colour_next = 0;

    offset = n->colour_next;
    if (offset >= cachep->colour)
        offset = 0;

    offset *= cachep->colour_off;

    /* Get slab management. */
    freelist = alloc_slabmgmt(cachep, slab, offset,
                              local_flags & ~GFP_CONSTRAINT_MASK,
                              slab_node);
    if (OFF_SLAB(cachep) && !freelist)
        goto opps1;

    slab->slab_cache = cachep;
    slab->freelist = freelist;

    cache_init_objs(cachep, slab);

    if (gfpflags_allow_blocking(local_flags))
        local_irq_disable();

    return slab;

 opps1:
    kmem_freepages(cachep, slab);
 failed:
    if (gfpflags_allow_blocking(local_flags))
        local_irq_disable();
    return NULL;
}

static void cache_grow_end(struct kmem_cache *cachep, struct slab *slab)
{
    struct kmem_cache_node *n;
    void *list = NULL;

    if (!slab)
        return;

    INIT_LIST_HEAD(&slab->slab_list);
    n = get_node(cachep, slab_nid(slab));

    spin_lock(&n->list_lock);
    n->total_slabs++;
    if (!slab->active) {
        list_add_tail(&slab->slab_list, &n->slabs_free);
        n->free_slabs++;
    } else
        fixup_slab_list(cachep, n, slab, &list);

    n->free_objects += cachep->num - slab->active;
    spin_unlock(&n->list_lock);
}

static void *cache_alloc_refill(struct kmem_cache *cachep, gfp_t flags)
{
    int batchcount;
    struct kmem_cache_node *n;
    struct array_cache *ac, *shared;
    int node;
    void *list = NULL;
    struct slab *slab;

    node = numa_mem_id();

    ac = cpu_cache_get(cachep);
    batchcount = ac->batchcount;
    if (!ac->touched && batchcount > BATCHREFILL_LIMIT) {
        /*
         * If there was little recent activity on this cache, then
         * perform only a partial refill.  Otherwise we could generate
         * refill bouncing.
         */
        batchcount = BATCHREFILL_LIMIT;
    }
    n = get_node(cachep, node);

    BUG_ON(ac->avail > 0 || !n);
    shared = READ_ONCE(n->shared);
    if (!n->free_objects && (!shared || !shared->avail))
        goto direct_grow;

    spin_lock(&n->list_lock);
    shared = READ_ONCE(n->shared);

    /* See if we can refill from the shared array */
    if (shared && transfer_objects(ac, shared, batchcount)) {
        shared->touched = 1;
        goto alloc_done;
    }

    while (batchcount > 0) {
        /* Get slab alloc is to come from. */
        slab = get_first_slab(n, false);
        if (!slab)
            goto must_grow;

        batchcount = alloc_block(cachep, ac, slab, batchcount);
        fixup_slab_list(cachep, n, slab, &list);
    }

 must_grow:
    n->free_objects -= ac->avail;

 alloc_done:
    spin_unlock(&n->list_lock);

 direct_grow:
    if (unlikely(!ac->avail)) {
#if 0
        /* Check if we can use obj in pfmemalloc slab */
        if (sk_memalloc_socks()) {
            void *obj = cache_alloc_pfmemalloc(cachep, n, flags);

            if (obj)
                return obj;
        }
#endif

        slab = cache_grow_begin(cachep, gfp_exact_node(flags), node);

        /*
         * cache_grow_begin() can reenable interrupts,
         * then ac could change.
         */
        ac = cpu_cache_get(cachep);
        if (!ac->avail && slab)
            alloc_block(cachep, ac, slab, batchcount);
        cache_grow_end(cachep, slab);

        if (!ac->avail)
            return NULL;
    }
    ac->touched = 1;

    return ac->entry[--ac->avail];
}

static inline void *____cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
    void *objp;
    struct array_cache *ac;

    ac = cpu_cache_get(cachep);
    if (likely(ac->avail)) {
        ac->touched = 1;
        objp = ac->entry[--ac->avail];

        goto out;
    }

    objp = cache_alloc_refill(cachep, flags);

 out:
    return objp;
}

static __always_inline void *
__do_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
    return ____cache_alloc(cachep, flags);
}

static __always_inline void *
slab_alloc(struct kmem_cache *cachep, gfp_t flags, size_t orig_size,
           unsigned long caller)
{
    unsigned long save_flags;
    void *objp;
    struct obj_cgroup *objcg = NULL;
    bool init = false;

    flags &= gfp_allowed_mask;
    cachep = slab_pre_alloc_hook(cachep, &objcg, 1, flags);
    if (unlikely(!cachep))
        return NULL;

    local_irq_save(save_flags);
    objp = __do_cache_alloc(cachep, flags);
    local_irq_restore(save_flags);
    prefetchw(objp);
    init = slab_want_init_on_alloc(flags, cachep);

    slab_post_alloc_hook(cachep, objcg, flags, 1, &objp, init);
    return objp;
}

/**
 * kmem_cache_alloc - Allocate an object
 * @cachep: The cache to allocate from.
 * @flags: See kmalloc().
 *
 * Allocate an object from this cache.  The flags are only relevant
 * if the cache has no available objects.
 *
 * Return: pointer to the new object or %NULL in case of error
 */
void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
    return slab_alloc(cachep, flags, cachep->object_size, _RET_IP_);
}
EXPORT_SYMBOL(kmem_cache_alloc);

static void kmem_cache_node_init(struct kmem_cache_node *parent)
{
    INIT_LIST_HEAD(&parent->slabs_full);
    INIT_LIST_HEAD(&parent->slabs_partial);
    INIT_LIST_HEAD(&parent->slabs_free);
    parent->total_slabs = 0;
    parent->free_slabs = 0;
    parent->shared = NULL;
    parent->alien = NULL;
    parent->colour_next = 0;
    spin_lock_init(&parent->list_lock);
    parent->free_objects = 0;
    parent->free_touched = 0;
}

#define MAKE_LIST(cachep, listp, slab, nodeid)              \
do {                                \
    INIT_LIST_HEAD(listp);                  \
    list_splice(&get_node(cachep, nodeid)->slab, listp);    \
} while (0)

#define MAKE_ALL_LISTS(cachep, ptr, nodeid)             \
do {                                \
    MAKE_LIST((cachep), (&(ptr)->slabs_full), slabs_full, nodeid);  \
    MAKE_LIST((cachep), (&(ptr)->slabs_partial), slabs_partial, nodeid); \
    MAKE_LIST((cachep), (&(ptr)->slabs_free), slabs_free, nodeid);  \
} while (0)

/*
 * swap the static kmem_cache_node with kmalloced memory
 */
static void __init
init_list(struct kmem_cache *cachep, struct kmem_cache_node *list, int nodeid)
{
    struct kmem_cache_node *ptr;

    ptr = kmalloc_node(sizeof(struct kmem_cache_node), GFP_NOWAIT, nodeid);
    BUG_ON(!ptr);

    memcpy(ptr, list, sizeof(struct kmem_cache_node));
    /*
     * Do not assume that spinlocks can be initialized via memcpy:
     */
    spin_lock_init(&ptr->list_lock);

    MAKE_ALL_LISTS(cachep, ptr, nodeid);
    cachep->node[nodeid] = ptr;
}

/*
 * Initialisation.  Called after the page allocator have been initialised and
 * before smp_init().
 */
void __init kmem_cache_init(void)
{
    int i;

    kmem_cache = &kmem_cache_boot;

    use_alien_caches = 0;

    for (i = 0; i < NUM_INIT_LISTS; i++)
        kmem_cache_node_init(&init_kmem_cache_node[i]);

    /*
     * Fragmentation resistance on low memory - only use bigger
     * page orders on machines with more than 32MB of memory if
     * not overridden on the command line.
     */
    if (!slab_max_order_set && totalram_pages() > (32 << 20) >> PAGE_SHIFT)
        slab_max_order = SLAB_MAX_ORDER_HI;

    /* Bootstrap is tricky, because several objects are allocated
     * from caches that do not exist yet:
     * 1) initialize the kmem_cache cache: it contains the struct
     *    kmem_cache structures of all caches, except kmem_cache itself:
     *    kmem_cache is statically allocated.
     *    Initially an __init data area is used for the head array and the
     *    kmem_cache_node structures, it's replaced with a kmalloc allocated
     *    array at the end of the bootstrap.
     * 2) Create the first kmalloc cache.
     *    The struct kmem_cache for the new cache is allocated normally.
     *    An __init data area is used for the head array.
     * 3) Create the remaining kmalloc caches, with minimally sized
     *    head arrays.
     * 4) Replace the __init data head arrays for kmem_cache and the first
     *    kmalloc cache with kmalloc allocated arrays.
     * 5) Replace the __init data for kmem_cache_node for kmem_cache and
     *    the other cache's with kmalloc allocated memory.
     * 6) Resize the head arrays of the kmalloc caches to their final sizes.
     */

    /* 1) create the kmem_cache */

    /*
     * struct kmem_cache size depends on nr_node_ids & nr_cpu_ids
     */
    create_boot_cache(kmem_cache, "kmem_cache",
                      offsetof(struct kmem_cache, node) +
                      nr_node_ids * sizeof(struct kmem_cache_node *),
                      SLAB_HWCACHE_ALIGN, 0, 0);

    list_add(&kmem_cache->list, &slab_caches);
    slab_state = PARTIAL;

    /*
     * Initialize the caches that provide memory for the  kmem_cache_node
     * structures first.  Without this, further allocations will bug.
     */
    kmalloc_caches[KMALLOC_NORMAL][INDEX_NODE] = create_kmalloc_cache(
            kmalloc_info[INDEX_NODE].name[KMALLOC_NORMAL],
            kmalloc_info[INDEX_NODE].size,
            ARCH_KMALLOC_FLAGS, 0,
            kmalloc_info[INDEX_NODE].size);
    slab_state = PARTIAL_NODE;
    setup_kmalloc_cache_index_table();

    slab_early_init = 0;

    /* 5) Replace the bootstrap kmem_cache_node */
    {
        int nid;

        for_each_online_node(nid) {
            init_list(kmem_cache,
                      &init_kmem_cache_node[CACHE_CACHE + nid], nid);

            init_list(kmalloc_caches[KMALLOC_NORMAL][INDEX_NODE],
                      &init_kmem_cache_node[SIZE_NODE + nid], nid);
        }
    }

    create_kmalloc_caches(ARCH_KMALLOC_FLAGS);
}

/*
 * Calculate the number of objects and left-over bytes for a given buffer size.
 */
static unsigned int
cache_estimate(unsigned long gfporder, size_t buffer_size,
               slab_flags_t flags, size_t *left_over)
{
    unsigned int num;
    size_t slab_size = PAGE_SIZE << gfporder;

    /*
     * The slab management structure can be either off the slab or
     * on it. For the latter case, the memory allocated for a
     * slab is used for:
     *
     * - @buffer_size bytes for each object
     * - One freelist_idx_t for each object
     *
     * We don't need to consider alignment of freelist because
     * freelist will be at the end of slab page. The objects will be
     * at the correct alignment.
     *
     * If the slab management structure is off the slab, then the
     * alignment will already be calculated into the size. Because
     * the slabs are all pages aligned, the objects will be at the
     * correct alignment when allocated.
     */
    if (flags & (CFLGS_OBJFREELIST_SLAB | CFLGS_OFF_SLAB)) {
        num = slab_size / buffer_size;
        *left_over = slab_size % buffer_size;
    } else {
        num = slab_size / (buffer_size + sizeof(freelist_idx_t));
        *left_over = slab_size % (buffer_size + sizeof(freelist_idx_t));
    }

    return num;
}

/**
 * calculate_slab_order - calculate size (page order) of slabs
 * @cachep: pointer to the cache that is being created
 * @size: size of objects to be created in this cache.
 * @flags: slab allocation flags
 *
 * Also calculates the number of objects per slab.
 *
 * This could be made much more intelligent.  For now, try to avoid using
 * high order pages for slabs.  When the gfp() functions are more friendly
 * towards high-order requests, this should be changed.
 *
 * Return: number of left-over bytes in a slab
 */
static size_t
calculate_slab_order(struct kmem_cache *cachep, size_t size, slab_flags_t flags)
{
    int gfporder;
    size_t left_over = 0;

    for (gfporder = 0; gfporder <= KMALLOC_MAX_ORDER; gfporder++) {
        unsigned int num;
        size_t remainder;

        num = cache_estimate(gfporder, size, flags, &remainder);
        if (!num)
            continue;

        /* Can't handle number of objects more than SLAB_OBJ_MAX_NUM */
        if (num > SLAB_OBJ_MAX_NUM)
            break;

        if (flags & CFLGS_OFF_SLAB) {
            size_t freelist_size;
            struct kmem_cache *freelist_cache;

            freelist_size = num * sizeof(freelist_idx_t);
            freelist_cache = kmalloc_slab(freelist_size, 0u);
            if (!freelist_cache)
                continue;

            /*
             * Needed to avoid possible looping condition
             * in cache_grow_begin()
             */
            if (OFF_SLAB(freelist_cache))
                continue;

            /* check if off slab has enough benefit */
            if (freelist_cache->size > cachep->size / 2)
                continue;
        }

        /* Found something acceptable - save it away */
        cachep->num = num;
        cachep->gfporder = gfporder;
        left_over = remainder;

        /*
         * A VFS-reclaimable slab tends to have most allocations
         * as GFP_NOFS and we really don't want to have to be allocating
         * higher-order pages when we are unable to shrink dcache.
         */
        if (flags & SLAB_RECLAIM_ACCOUNT)
            break;

        /*
         * Large number of objects is good, but very large slabs are
         * currently bad for the gfp()s.
         */
        if (gfporder >= slab_max_order)
            break;

        /*
         * Acceptable internal fragmentation?
         */
        if (left_over * 8 <= (PAGE_SIZE << gfporder))
            break;
    }
    return left_over;
}

static bool set_objfreelist_slab_cache(struct kmem_cache *cachep,
                                       size_t size, slab_flags_t flags)
{
    size_t left;

    cachep->num = 0;

    /*
     * If slab auto-initialization on free is enabled, store the freelist
     * off-slab, so that its contents don't end up in one of the allocated
     * objects.
     */
    if (unlikely(slab_want_init_on_free(cachep)))
        return false;

    if (cachep->ctor || flags & SLAB_TYPESAFE_BY_RCU)
        return false;

    left = calculate_slab_order(cachep, size, flags | CFLGS_OBJFREELIST_SLAB);
    if (!cachep->num)
        return false;

    if (cachep->num * sizeof(freelist_idx_t) > cachep->object_size)
        return false;

    cachep->colour = left / cachep->colour_off;
    return true;
}

static bool set_off_slab_cache(struct kmem_cache *cachep,
                               size_t size, slab_flags_t flags)
{
    size_t left;

    cachep->num = 0;

    /*
     * Always use on-slab management when SLAB_NOLEAKTRACE
     * to avoid recursive calls into kmemleak.
     */
    if (flags & SLAB_NOLEAKTRACE)
        return false;

    /*
     * Size is large, assume best to place the slab management obj
     * off-slab (should allow better packing of objs).
     */
    left = calculate_slab_order(cachep, size, flags | CFLGS_OFF_SLAB);
    if (!cachep->num)
        return false;

    /*
     * If the slab has been placed off-slab, and we have enough space then
     * move it on-slab. This is at the expense of any extra colouring.
     */
    if (left >= cachep->num * sizeof(freelist_idx_t))
        return false;

    cachep->colour = left / cachep->colour_off;
    return true;
}

static bool
set_on_slab_cache(struct kmem_cache *cachep, size_t size, slab_flags_t flags)
{
    size_t left;

    cachep->num = 0;

    left = calculate_slab_order(cachep, size, flags);
    if (!cachep->num)
        return false;

    cachep->colour = left / cachep->colour_off;
    return true;
}

static void init_arraycache(struct array_cache *ac, int limit, int batch)
{
    if (ac) {
        ac->avail = 0;
        ac->limit = limit;
        ac->batchcount = batch;
        ac->touched = 0;
    }
}

static struct array_cache __percpu *
alloc_kmem_cache_cpus(struct kmem_cache *cachep, int entries, int batchcount)
{
    int cpu;
    size_t size;
    struct array_cache __percpu *cpu_cache;

    size = sizeof(void *) * entries + sizeof(struct array_cache);
    cpu_cache = __alloc_percpu(size, sizeof(void *));

    if (!cpu_cache)
        return NULL;

    for_each_possible_cpu(cpu) {
        init_arraycache(per_cpu_ptr(cpu_cache, cpu), entries, batchcount);
    }

    return cpu_cache;
}

static void slab_put_obj(struct kmem_cache *cachep,
                         struct slab *slab, void *objp)
{
    unsigned int objnr = obj_to_index(cachep, slab, objp);

    slab->active--;
    if (!slab->freelist)
        slab->freelist = objp + obj_offset(cachep);

    set_free_obj(slab, slab->active, objnr);
}

/*
 * Caller needs to acquire correct kmem_cache_node's list_lock
 * @list: List of detached free slabs should be freed by caller
 */
static void
free_block(struct kmem_cache *cachep, void **objpp,
           int nr_objects, int node, struct list_head *list)
{
    int i;
    struct kmem_cache_node *n = get_node(cachep, node);
    struct slab *slab;

    n->free_objects += nr_objects;

    for (i = 0; i < nr_objects; i++) {
        void *objp;
        struct slab *slab;

        objp = objpp[i];

        slab = virt_to_slab(objp);
        list_del(&slab->slab_list);
        slab_put_obj(cachep, slab, objp);

        /* fixup slab chains */
        if (slab->active == 0) {
            list_add(&slab->slab_list, &n->slabs_free);
            n->free_slabs++;
        } else {
            /* Unconditionally move a slab to the end of the
             * partial list on free - maximum time for the
             * other objects to be freed, too.
             */
            list_add_tail(&slab->slab_list, &n->slabs_partial);
        }
    }

    while (n->free_objects > n->free_limit &&
           !list_empty(&n->slabs_free)) {
        n->free_objects -= cachep->num;

        slab = list_last_entry(&n->slabs_free, struct slab, slab_list);
        list_move(&slab->slab_list, list);
        n->free_slabs--;
        n->total_slabs--;
    }
}

static void kmem_rcu_free(struct rcu_head *head)
{
    struct kmem_cache *cachep;
    struct slab *slab;

    slab = container_of(head, struct slab, rcu_head);
    cachep = slab->slab_cache;

    kmem_freepages(cachep, slab);
}

/**
 * slab_destroy - destroy and release all objects in a slab
 * @cachep: cache pointer being destroyed
 * @page: page pointer being destroyed
 *
 * Destroy all the objs in a slab page, and release the mem back to the system.
 * Before calling the slab page must have been unlinked from the cache. The
 * kmem_cache_node ->list_lock is not held/needed.
 */
static void slab_destroy(struct kmem_cache *cachep, struct slab *slab)
{
    void *freelist;

    freelist = slab->freelist;
    if (unlikely(cachep->flags & SLAB_TYPESAFE_BY_RCU))
        call_rcu(&slab->rcu_head, kmem_rcu_free);
    else
        kmem_freepages(cachep, slab);

    /*
     * From now on, we don't use freelist
     * although actual page can be freed in rcu context
     */
    if (OFF_SLAB(cachep))
        kmem_cache_free(cachep->freelist_cache, freelist);
}

/*
 * Update the size of the caches before calling slabs_destroy as it may
 * recursively call kfree.
 */
static void slabs_destroy(struct kmem_cache *cachep,
                          struct list_head *list)
{
    struct slab *slab, *n;

    list_for_each_entry_safe(slab, n, list, slab_list) {
        list_del(&slab->slab_list);
        slab_destroy(cachep, slab);
    }
}

static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
{
    int batchcount;
    struct kmem_cache_node *n;
    int node = numa_mem_id();
    LIST_HEAD(list);

    batchcount = ac->batchcount;

    n = get_node(cachep, node);
    spin_lock(&n->list_lock);
    if (n->shared) {
        struct array_cache *shared_array = n->shared;
        int max = shared_array->limit - shared_array->avail;
        if (max) {
            if (batchcount > max)
                batchcount = max;
            memcpy(&(shared_array->entry[shared_array->avail]),
                   ac->entry, sizeof(void *) * batchcount);
            shared_array->avail += batchcount;
            goto free_done;
        }
    }

    free_block(cachep, ac->entry, batchcount, node, &list);

 free_done:
    spin_unlock(&n->list_lock);
    ac->avail -= batchcount;
    memmove(ac->entry, &(ac->entry[batchcount]), sizeof(void *)*ac->avail);
    slabs_destroy(cachep, &list);
}

/* &alien->lock must be held by alien callers. */
static __always_inline void __free_one(struct array_cache *ac, void *objp)
{
    /* Avoid trivial double-free. */
    ac->entry[ac->avail++] = objp;
}

void ___cache_free(struct kmem_cache *cachep, void *objp, unsigned long caller)
{
    struct array_cache *ac = cpu_cache_get(cachep);

    if (ac->avail >= ac->limit)
        cache_flusharray(cachep, ac);

#if 0
    if (sk_memalloc_socks()) {
        struct page *page = virt_to_head_page(objp);

        if (unlikely(PageSlabPfmemalloc(page))) {
            cache_free_pfmemalloc(cachep, page, objp);
            return;
        }
    }
#endif

    __free_one(ac, objp);
}

/*
 * Release an obj back to its cache. If the obj has a constructed state, it must
 * be in this state _before_ it is released.  Called with disabled ints.
 */
static __always_inline void
__cache_free(struct kmem_cache *cachep, void *objp, unsigned long caller)
{
    bool init;

    /*
     * As memory initialization might be integrated into KASAN,
     * kasan_slab_free and initialization memset must be
     * kept together to avoid discrepancies in behavior.
     */
    init = slab_want_init_on_free(cachep);
    if (init)
        memset(objp, 0, cachep->object_size);

    ___cache_free(cachep, objp, caller);
}

/**
 * kmem_cache_free - Deallocate an object
 * @cachep: The cache the allocation was from.
 * @objp: The previously allocated object.
 *
 * Free an object which was previously allocated from this
 * cache.
 */
void kmem_cache_free(struct kmem_cache *cachep, void *objp)
{
    unsigned long flags;
    if (!cachep)
        return;

    local_irq_save(flags);
    __cache_free(cachep, objp, _RET_IP_);
    local_irq_restore(flags);
}
EXPORT_SYMBOL(kmem_cache_free);

static struct array_cache *
alloc_arraycache(int node, int entries, int batchcount, gfp_t gfp)
{
    struct array_cache *ac = NULL;
    size_t memsize = sizeof(void *) * entries + sizeof(struct array_cache);

    ac = kmalloc_node(memsize, gfp, node);
    /*
     * The array_cache structures contain pointers to free object.
     * However, when such objects are allocated or transferred to another
     * cache the pointers are not cleared and they could be counted as
     * valid references during a kmemleak scan. Therefore, kmemleak must
     * not scan such objects.
     */
    init_arraycache(ac, entries, batchcount);
    return ac;
}

static int init_cache_node(struct kmem_cache *cachep, int node, gfp_t gfp)
{
    struct kmem_cache_node *n;

    /*
     * Set up the kmem_cache_node for cpu before we can
     * begin anything. Make sure some other cpu on this
     * node has not already allocated this
     */
    n = get_node(cachep, node);
    if (n) {
        spin_lock_irq(&n->list_lock);
        n->free_limit = (1 + nr_cpus_node(node)) * cachep->batchcount +
                cachep->num;
        spin_unlock_irq(&n->list_lock);

        return 0;
    }

    n = kmalloc_node(sizeof(struct kmem_cache_node), gfp, node);
    if (!n)
        return -ENOMEM;

    kmem_cache_node_init(n);
    n->next_reap = jiffies + REAPTIMEOUT_NODE +
            ((unsigned long)cachep) % REAPTIMEOUT_NODE;

    n->free_limit =
        (1 + nr_cpus_node(node)) * cachep->batchcount + cachep->num;

    /*
     * The kmem_cache_nodes don't come and go as CPUs
     * come and go.  slab_mutex is sufficient
     * protection here.
     */
    cachep->node[node] = n;

    return 0;
}

static int
setup_kmem_cache_node(struct kmem_cache *cachep,
                      int node, gfp_t gfp, bool force_change)
{
    int ret = -ENOMEM;
    struct kmem_cache_node *n;
    struct array_cache *old_shared = NULL;
    struct array_cache *new_shared = NULL;
    struct alien_cache **new_alien = NULL;
    LIST_HEAD(list);

    if (use_alien_caches) {
        panic("%s: NOT support alien caches.\n", __func__);
    }

    if (cachep->shared) {
        new_shared = alloc_arraycache(node, cachep->shared * cachep->batchcount,
                                      0xbaadf00d, gfp);
        if (!new_shared)
            goto fail;
    }

    ret = init_cache_node(cachep, node, gfp);
    if (ret)
        goto fail;

    n = get_node(cachep, node);
    spin_lock_irq(&n->list_lock);
    if (n->shared && force_change) {
        free_block(cachep, n->shared->entry, n->shared->avail, node, &list);
        n->shared->avail = 0;
    }

    if (!n->shared || force_change) {
        old_shared = n->shared;
        n->shared = new_shared;
        new_shared = NULL;
    }

    if (!n->alien) {
        n->alien = new_alien;
        new_alien = NULL;
    }

    spin_unlock_irq(&n->list_lock);
    slabs_destroy(cachep, &list);

    /*
     * To protect lockless access to n->shared during irq disabled context.
     * If n->shared isn't NULL in irq disabled context, accessing to it is
     * guaranteed to be valid until irq is re-enabled, because it will be
     * freed after synchronize_rcu().
     */
    if (old_shared && force_change)
        synchronize_rcu();

 fail:
    kfree(old_shared);
    kfree(new_shared);

    return ret;
}

/*
 * This initializes kmem_cache_node or resizes various caches for all nodes.
 */
static int setup_kmem_cache_nodes(struct kmem_cache *cachep, gfp_t gfp)
{
    int ret;
    int node;
    struct kmem_cache_node *n;

    for_each_online_node(node) {
        ret = setup_kmem_cache_node(cachep, node, gfp, true);
        if (ret)
            goto fail;

    }

    return 0;

fail:
    if (!cachep->list.next) {
        /* Cache is not active yet. Roll back what we did */
        node--;
        while (node >= 0) {
            n = get_node(cachep, node);
            if (n) {
                kfree(n->shared);
                kfree(n);
                cachep->node[node] = NULL;
            }
            node--;
        }
    }
    return -ENOMEM;
}

/* Always called with the slab_mutex held */
static int do_tune_cpucache(struct kmem_cache *cachep, int limit,
                            int batchcount, int shared, gfp_t gfp)
{
    int cpu;
    struct array_cache __percpu *cpu_cache, *prev;

    cpu_cache = alloc_kmem_cache_cpus(cachep, limit, batchcount);
    if (!cpu_cache)
        return -ENOMEM;

    prev = cachep->cpu_cache;
    cachep->cpu_cache = cpu_cache;
#if 0
    /*
     * Without a previous cpu_cache there's no need to synchronize remote
     * cpus, so skip the IPIs.
     */
    if (prev)
        kick_all_cpus_sync();
#endif

    cachep->batchcount = batchcount;
    cachep->limit = limit;
    cachep->shared = shared;

    if (!prev)
        goto setup_node;

    for_each_online_cpu(cpu) {
        int node;
        LIST_HEAD(list);
        struct kmem_cache_node *n;
        struct array_cache *ac = per_cpu_ptr(prev, cpu);

        node = cpu_to_mem(cpu);
        n = get_node(cachep, node);
        spin_lock_irq(&n->list_lock);
        free_block(cachep, ac->entry, ac->avail, node, &list);
        spin_unlock_irq(&n->list_lock);
        slabs_destroy(cachep, &list);
    }
    free_percpu(prev);

 setup_node:
    return setup_kmem_cache_nodes(cachep, gfp);
}

/* Called with slab_mutex held always */
static int enable_cpucache(struct kmem_cache *cachep, gfp_t gfp)
{
    int err;
    int limit = 0;
    int shared = 0;
    int batchcount = 0;

    /*
     * The head array serves three purposes:
     * - create a LIFO ordering, i.e. return objects that are cache-warm
     * - reduce the number of spinlock operations.
     * - reduce the number of linked list operations on the slab and
     *   bufctl chains: array operations are cheaper.
     * The numbers are guessed, we should auto-tune as described by
     * Bonwick.
     */
    if (cachep->size > 131072)
        limit = 1;
    else if (cachep->size > PAGE_SIZE)
        limit = 8;
    else if (cachep->size > 1024)
        limit = 24;
    else if (cachep->size > 256)
        limit = 54;
    else
        limit = 120;

    /*
     * CPU bound tasks (e.g. network routing) can exhibit cpu bound
     * allocation behaviour: Most allocs on one cpu, most free operations
     * on another cpu. For these cases, an efficient object passing between
     * cpus is necessary. This is provided by a shared array. The array
     * replaces Bonwick's magazine layer.
     * On uniprocessor, it's functionally equivalent (but less efficient)
     * to a larger limit. Thus disabled by default.
     */
    shared = 0;
    if (cachep->size <= PAGE_SIZE && num_possible_cpus() > 1)
        shared = 8;

    batchcount = (limit + 1) / 2;
    err = do_tune_cpucache(cachep, limit, batchcount, shared, gfp);

    if (err)
        pr_err("enable_cpucache failed for %s, error %d\n", cachep->name, -err);

    return err;
}

/*
 * For setting up all the kmem_cache_node for cache whose buffer_size is same as
 * size of kmem_cache_node.
 */
static void __init set_up_node(struct kmem_cache *cachep, int index)
{
    int node;

    for_each_online_node(node) {
        cachep->node[node] = &init_kmem_cache_node[index + node];
        cachep->node[node]->next_reap = jiffies + REAPTIMEOUT_NODE +
            ((unsigned long)cachep) % REAPTIMEOUT_NODE;
    }
}

static int __ref setup_cpu_cache(struct kmem_cache *cachep, gfp_t gfp)
{
    if (slab_state >= FULL)
        return enable_cpucache(cachep, gfp);

    cachep->cpu_cache = alloc_kmem_cache_cpus(cachep, 1, 1);
    if (!cachep->cpu_cache)
        return 1;

    if (slab_state == DOWN) {
        /* Creation of first cache (kmem_cache). */
        set_up_node(kmem_cache, CACHE_CACHE);
    } else if (slab_state == PARTIAL) {
        /* For kmem_cache_node */
        set_up_node(cachep, SIZE_NODE);
    } else {
        int node;

        for_each_online_node(node) {
            cachep->node[node] = kmalloc_node(
                sizeof(struct kmem_cache_node), gfp, node);
            BUG_ON(!cachep->node[node]);
            kmem_cache_node_init(cachep->node[node]);
        }
    }

    cachep->node[numa_mem_id()]->next_reap =
        jiffies + REAPTIMEOUT_NODE +
        ((unsigned long)cachep) % REAPTIMEOUT_NODE;

    cpu_cache_get(cachep)->avail = 0;
    cpu_cache_get(cachep)->limit = BOOT_CPUCACHE_ENTRIES;
    cpu_cache_get(cachep)->batchcount = 1;
    cpu_cache_get(cachep)->touched = 0;
    cachep->batchcount = 1;
    cachep->limit = BOOT_CPUCACHE_ENTRIES;

    return 0;
}

void __kmem_cache_release(struct kmem_cache *cachep)
{
    int i;
    struct kmem_cache_node *n;

    free_percpu(cachep->cpu_cache);

    /* NUMA: free the node structures */
    for_each_kmem_cache_node(cachep, i, n) {
        kfree(n->shared);
        kfree(n);
        cachep->node[i] = NULL;
    }
}

/**
 * __kmem_cache_create - Create a cache.
 * @cachep: cache management descriptor
 * @flags: SLAB flags
 *
 * Returns a ptr to the cache on success, NULL on failure.
 * Cannot be called within a int, but can be interrupted.
 * The @ctor is run when new pages are allocated by the cache.
 *
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialised memory.
 *
 * %SLAB_RED_ZONE - Insert `Red' zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline.  This can be beneficial if you're counting cycles as closely
 * as davem.
 *
 * Return: a pointer to the created cache or %NULL in case of error
 */
int __kmem_cache_create(struct kmem_cache *cachep, slab_flags_t flags)
{
    int err;
    gfp_t gfp;
    size_t ralign = BYTES_PER_WORD;
    unsigned int size = cachep->size;

    /*
     * Check that size is in terms of words.  This is needed to avoid
     * unaligned accesses for some archs when redzoning is used, and makes
     * sure any on-slab bufctl's are also correctly aligned.
     */
    size = ALIGN(size, BYTES_PER_WORD);

    if (flags & SLAB_RED_ZONE) {
        ralign = REDZONE_ALIGN;
        /* If redzoning, ensure that the second redzone is suitably
         * aligned, by adjusting the object size accordingly. */
        size = ALIGN(size, REDZONE_ALIGN);
    }

    /* 3) caller mandated alignment */
    if (ralign < cachep->align) {
        ralign = cachep->align;
    }
    /* disable debug if necessary */
    if (ralign > __alignof__(unsigned long long))
        flags &= ~(SLAB_RED_ZONE | SLAB_STORE_USER);

    /*
     * 4) Store it.
     */
    cachep->align = ralign;
    cachep->colour_off = cache_line_size();
    /* Offset must be a multiple of the alignment. */
    if (cachep->colour_off < cachep->align)
        cachep->colour_off = cachep->align;

    if (slab_is_available())
        gfp = GFP_KERNEL;
    else
        gfp = GFP_NOWAIT;

    size = ALIGN(size, cachep->align);
    /*
     * We should restrict the number of objects in a slab to implement
     * byte sized index. Refer comment on SLAB_OBJ_MIN_SIZE definition.
     */
    if (FREELIST_BYTE_INDEX && size < SLAB_OBJ_MIN_SIZE)
        size = ALIGN(SLAB_OBJ_MIN_SIZE, cachep->align);

    if (set_objfreelist_slab_cache(cachep, size, flags)) {
        flags |= CFLGS_OBJFREELIST_SLAB;
        goto done;
    }

    if (set_off_slab_cache(cachep, size, flags)) {
        flags |= CFLGS_OFF_SLAB;
        goto done;
    }

    if (set_on_slab_cache(cachep, size, flags))
        goto done;

    return -E2BIG;

 done:
    cachep->freelist_size = cachep->num * sizeof(freelist_idx_t);
    cachep->flags = flags;
    cachep->allocflags = __GFP_COMP;
    if (flags & SLAB_CACHE_DMA)
        cachep->allocflags |= GFP_DMA;
    if (flags & SLAB_CACHE_DMA32)
        cachep->allocflags |= GFP_DMA32;
    if (flags & SLAB_RECLAIM_ACCOUNT)
        cachep->allocflags |= __GFP_RECLAIMABLE;
    cachep->size = size;
    cachep->reciprocal_buffer_size = reciprocal_value(size);

    if (OFF_SLAB(cachep)) {
        cachep->freelist_cache = kmalloc_slab(cachep->freelist_size, 0u);
    }

    err = setup_cpu_cache(cachep, gfp);
    if (err) {
        __kmem_cache_release(cachep);
        return err;
    }

    return 0;
}

/**
 * __do_kmalloc - allocate memory
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate (see kmalloc).
 * @caller: function caller for debug tracking of the caller
 *
 * Return: pointer to the allocated memory or %NULL in case of error
 */
static __always_inline void *
__do_kmalloc(size_t size, gfp_t flags, unsigned long caller)
{
    void *ret;
    struct kmem_cache *cachep;

    if (unlikely(size > KMALLOC_MAX_CACHE_SIZE))
        return NULL;
    cachep = kmalloc_slab(size, flags);
    if (unlikely(ZERO_OR_NULL_PTR(cachep)))
        return cachep;
    ret = slab_alloc(cachep, flags, size, caller);
    return ret;
}

void *__kmalloc(size_t size, gfp_t flags)
{
    return __do_kmalloc(size, flags, _RET_IP_);
}
EXPORT_SYMBOL(__kmalloc);

void __init kmem_cache_init_late(void)
{
    struct kmem_cache *cachep;

    /* 6) resize the head arrays to their final sizes */
    mutex_lock(&slab_mutex);
    list_for_each_entry(cachep, &slab_caches, list)
        if (enable_cpucache(cachep, GFP_NOWAIT))
            BUG();
    mutex_unlock(&slab_mutex);

    /* Done! */
    slab_state = FULL;

    /*
     * The reap timers are started later, with a module init call: That part
     * of the kernel is not yet operational.
     */
}

struct kmem_cache *
__kmem_cache_alias(const char *name, unsigned int size, unsigned int align,
                   slab_flags_t flags, void (*ctor)(void *))
{
    struct kmem_cache *cachep;

    cachep = find_mergeable(size, align, flags, name, ctor);
    if (cachep) {
        cachep->refcount++;

        /*
         * Adjust the object sizes so that we clear
         * the complete object on kzalloc.
         */
        cachep->object_size = max_t(int, cachep->object_size, size);
    }
    return cachep;
}

slab_flags_t kmem_cache_flags(unsigned int object_size,
                              slab_flags_t flags, const char *name)
{
    return flags;
}

void *__kmalloc_track_caller(size_t size, gfp_t flags, unsigned long caller)
{
    return __do_kmalloc(size, flags, caller);
}
EXPORT_SYMBOL(__kmalloc_track_caller);

static __always_inline
void *__kmem_cache_alloc_lru(struct kmem_cache *cachep, struct list_lru *lru,
                             gfp_t flags)
{
    void *ret = slab_alloc(cachep, flags, cachep->object_size, _RET_IP_);
    return ret;
}

void *kmem_cache_alloc_lru(struct kmem_cache *cachep,
                           struct list_lru *lru,
                           gfp_t flags)
{
    return __kmem_cache_alloc_lru(cachep, lru, flags);
}
EXPORT_SYMBOL(kmem_cache_alloc_lru);

/**
 * kfree - free previously allocated memory
 * @objp: pointer returned by kmalloc.
 *
 * If @objp is NULL, no operation is performed.
 *
 * Don't free memory not originally allocated by kmalloc()
 * or you will run into trouble.
 */
void kfree(const void *objp)
{
    struct kmem_cache *c;
    unsigned long flags;

    if (unlikely(ZERO_OR_NULL_PTR(objp)))
        return;
    local_irq_save(flags);
    c = virt_to_cache(objp);
    if (!c) {
        local_irq_restore(flags);
        return;
    }

    __cache_free(c, (void *)objp, _RET_IP_);
    local_irq_restore(flags);
}
EXPORT_SYMBOL(kfree);

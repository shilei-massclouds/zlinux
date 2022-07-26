// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2001 Jens Axboe <axboe@kernel.dk>
 */
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#if 0
#include <linux/uio.h>
#include <linux/iocontext.h>
#endif
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/mempool.h>
//#include <linux/workqueue.h>
//#include <linux/cgroup.h>
#include <linux/highmem.h>
//#include <linux/sched/sysctl.h>
//#include <linux/blk-crypto.h>
#include <linux/xarray.h>

#include "blk.h"
//#include "blk-rq-qos.h"
//#include "blk-cgroup.h"

struct bio_alloc_cache {
    struct bio      *free_list;
    unsigned int    nr;
};

static struct biovec_slab {
    int nr_vecs;
    char *name;
    struct kmem_cache *slab;
} bvec_slabs[] __read_mostly = {
    { .nr_vecs = 16, .name = "biovec-16" },
    { .nr_vecs = 64, .name = "biovec-64" },
    { .nr_vecs = 128, .name = "biovec-128" },
    { .nr_vecs = BIO_MAX_VECS, .name = "biovec-max" },
};

/*
 * Our slab pool management
 */
struct bio_slab {
    struct kmem_cache *slab;
    unsigned int slab_ref;
    unsigned int slab_size;
    char name[8];
};
static DEFINE_MUTEX(bio_slab_lock);
static DEFINE_XARRAY(bio_slabs);

static struct biovec_slab *biovec_slab(unsigned short nr_vecs)
{
    switch (nr_vecs) {
    /* smaller bios use inline vecs */
    case 5 ... 16:
        return &bvec_slabs[0];
    case 17 ... 64:
        return &bvec_slabs[1];
    case 65 ... 128:
        return &bvec_slabs[2];
    case 129 ... BIO_MAX_VECS:
        return &bvec_slabs[3];
    default:
        BUG();
        return NULL;
    }
}

/*
 * fs_bio_set is the bio_set containing bio and iovec memory pools used by
 * IO code that does not need private memory pools.
 */
struct bio_set fs_bio_set;
EXPORT_SYMBOL(fs_bio_set);

static void punt_bios_to_rescuer(struct bio_set *bs)
{
    panic("%s: END!\n", __func__);
}

/*
 * Users of this function have their own bio allocation. Subsequently,
 * they must remember to pair any call to bio_init() with bio_uninit()
 * when IO has completed, or when the bio is released.
 */
void bio_init(struct bio *bio, struct block_device *bdev, struct bio_vec *table,
              unsigned short max_vecs, unsigned int opf)
{
    bio->bi_next = NULL;
    bio->bi_bdev = bdev;
    bio->bi_opf = opf;
    bio->bi_flags = 0;
    bio->bi_ioprio = 0;
    bio->bi_status = 0;
    bio->bi_iter.bi_sector = 0;
    bio->bi_iter.bi_size = 0;
    bio->bi_iter.bi_idx = 0;
    bio->bi_iter.bi_bvec_done = 0;
    bio->bi_end_io = NULL;
    bio->bi_private = NULL;
    bio->bi_vcnt = 0;

    atomic_set(&bio->__bi_remaining, 1);
    atomic_set(&bio->__bi_cnt, 1);
#if 0
    bio->bi_cookie = BLK_QC_T_NONE;
#endif

    bio->bi_max_vecs = max_vecs;
    bio->bi_io_vec = table;
    bio->bi_pool = NULL;
}
EXPORT_SYMBOL(bio_init);

/**
 * bio_alloc_bioset - allocate a bio for I/O
 * @bdev:   block device to allocate the bio for (can be %NULL)
 * @nr_vecs:    number of bvecs to pre-allocate
 * @opf:    operation and flags for bio
 * @gfp_mask:   the GFP_* mask given to the slab allocator
 * @bs:     the bio_set to allocate from.
 *
 * Allocate a bio from the mempools in @bs.
 *
 * If %__GFP_DIRECT_RECLAIM is set then bio_alloc will always be able to
 * allocate a bio.  This is due to the mempool guarantees.  To make this work,
 * callers must never allocate more than 1 bio at a time from the general pool.
 * Callers that need to allocate more than 1 bio must always submit the
 * previously allocated bio for IO before attempting to allocate a new one.
 * Failure to do so can cause deadlocks under memory pressure.
 *
 * Note that when running under submit_bio_noacct() (i.e. any block driver),
 * bios are not submitted until after you return - see the code in
 * submit_bio_noacct() that converts recursion into iteration, to prevent
 * stack overflows.
 *
 * This would normally mean allocating multiple bios under submit_bio_noacct()
 * would be susceptible to deadlocks, but we have
 * deadlock avoidance code that resubmits any blocked bios from a rescuer
 * thread.
 *
 * However, we do not guarantee forward progress for allocations from other
 * mempools. Doing multiple allocations from the same mempool under
 * submit_bio_noacct() should be avoided - instead, use bio_set's front_pad
 * for per bio allocations.
 *
 * Returns: Pointer to new bio on success, NULL on failure.
 */
struct bio *
bio_alloc_bioset(struct block_device *bdev, unsigned short nr_vecs,
                 unsigned int opf, gfp_t gfp_mask,
                 struct bio_set *bs)
{
    gfp_t saved_gfp = gfp_mask;
    struct bio *bio;
    void *p;

    /* should not use nobvec bioset for nr_vecs > 0 */
    if (WARN_ON_ONCE(!mempool_initialized(&bs->bvec_pool) && nr_vecs > 0))
        return NULL;

    /*
     * submit_bio_noacct() converts recursion to iteration; this means if
     * we're running beneath it, any bios we allocate and submit will not be
     * submitted (and thus freed) until after we return.
     *
     * This exposes us to a potential deadlock if we allocate multiple bios
     * from the same bio_set() while running underneath submit_bio_noacct().
     * If we were to allocate multiple bios (say a stacking block driver
     * that was splitting bios), we would deadlock if we exhausted the
     * mempool's reserve.
     *
     * We solve this, and guarantee forward progress, with a rescuer
     * workqueue per bio_set. If we go to allocate and there are bios on
     * current->bio_list, we first try the allocation without
     * __GFP_DIRECT_RECLAIM; if that fails, we punt those bios we would be
     * blocking to the rescuer workqueue before we retry with the original
     * gfp_flags.
     */
#if 0
    if (current->bio_list &&
        (!bio_list_empty(&current->bio_list[0]) ||
         !bio_list_empty(&current->bio_list[1])) &&
        bs->rescue_workqueue)
        gfp_mask &= ~__GFP_DIRECT_RECLAIM;
#else
    if (current->bio_list &&
        (!bio_list_empty(&current->bio_list[0]) ||
         !bio_list_empty(&current->bio_list[1])))
        gfp_mask &= ~__GFP_DIRECT_RECLAIM;
#endif

    p = mempool_alloc(&bs->bio_pool, gfp_mask);
    if (!p && gfp_mask != saved_gfp) {
        punt_bios_to_rescuer(bs);
        gfp_mask = saved_gfp;
        p = mempool_alloc(&bs->bio_pool, gfp_mask);
    }
    if (unlikely(!p))
        return NULL;

    bio = p + bs->front_pad;
    if (nr_vecs > BIO_INLINE_VECS) {
        panic("%s: > BIO_INLINE_VECS!\n", __func__);
    } else if (nr_vecs) {
        bio_init(bio, bdev, bio->bi_inline_vecs, BIO_INLINE_VECS, opf);
    } else {
        bio_init(bio, bdev, NULL, 0, opf);
    }

    bio->bi_pool = bs;
    return bio;

err_free:
    mempool_free(p, &bs->bio_pool);
    return NULL;
}
EXPORT_SYMBOL(bio_alloc_bioset);

static inline unsigned int bs_bio_slab_size(struct bio_set *bs)
{
    return bs->front_pad + sizeof(struct bio) + bs->back_pad;
}

static struct bio_slab *create_bio_slab(unsigned int size)
{
    struct bio_slab *bslab = kzalloc(sizeof(*bslab), GFP_KERNEL);

    if (!bslab)
        return NULL;

    snprintf(bslab->name, sizeof(bslab->name), "bio-%d", size);
    bslab->slab =
        kmem_cache_create(bslab->name, size,
                          ARCH_KMALLOC_MINALIGN,
                          SLAB_HWCACHE_ALIGN | SLAB_TYPESAFE_BY_RCU, NULL);
    if (!bslab->slab)
        goto fail_alloc_slab;

    bslab->slab_ref = 1;
    bslab->slab_size = size;

    if (!xa_err(xa_store(&bio_slabs, size, bslab, GFP_KERNEL)))
        return bslab;

    kmem_cache_destroy(bslab->slab);

fail_alloc_slab:
    kfree(bslab);
    return NULL;
}

static struct kmem_cache *bio_find_or_create_slab(struct bio_set *bs)
{
    unsigned int size = bs_bio_slab_size(bs);
    struct bio_slab *bslab;

    mutex_lock(&bio_slab_lock);
    bslab = xa_load(&bio_slabs, size);
    if (bslab)
        bslab->slab_ref++;
    else
        bslab = create_bio_slab(size);
    mutex_unlock(&bio_slab_lock);

    if (bslab)
        return bslab->slab;
    return NULL;
}

static inline bool
page_is_mergeable(const struct bio_vec *bv,
                  struct page *page, unsigned int len, unsigned int off,
                  bool *same_page)
{
    size_t bv_end = bv->bv_offset + bv->bv_len;
    phys_addr_t vec_end_addr = page_to_phys(bv->bv_page) + bv_end - 1;
    phys_addr_t page_addr = page_to_phys(page);

    if (vec_end_addr + 1 != page_addr + off)
        return false;

    *same_page = ((vec_end_addr & PAGE_MASK) == page_addr);
    if (*same_page)
        return true;
    return (bv->bv_page + bv_end / PAGE_SIZE) == (page + off / PAGE_SIZE);
}

/**
 * __bio_try_merge_page - try appending data to an existing bvec.
 * @bio: destination bio
 * @page: start page to add
 * @len: length of the data to add
 * @off: offset of the data relative to @page
 * @same_page: return if the segment has been merged inside the same page
 *
 * Try to add the data at @page + @off to the last bvec of @bio.  This is a
 * useful optimisation for file systems with a block size smaller than the
 * page size.
 *
 * Warn if (@len, @off) crosses pages in case that @same_page is true.
 *
 * Return %true on success or %false on failure.
 */
static bool
__bio_try_merge_page(struct bio *bio, struct page *page,
                     unsigned int len, unsigned int off, bool *same_page)
{
    if (WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED)))
        return false;

    if (bio->bi_vcnt > 0) {
        struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt - 1];

        if (page_is_mergeable(bv, page, len, off, same_page)) {
            if (bio->bi_iter.bi_size > UINT_MAX - len) {
                *same_page = false;
                return false;
            }
            bv->bv_len += len;
            bio->bi_iter.bi_size += len;
            return true;
        }
    }
    return false;
}

/**
 * bio_full - check if the bio is full
 * @bio:    bio to check
 * @len:    length of one segment to be added
 *
 * Return true if @bio is full and one segment with @len bytes can't be
 * added to the bio, otherwise return false
 */
static inline bool bio_full(struct bio *bio, unsigned len)
{
    if (bio->bi_vcnt >= bio->bi_max_vecs)
        return true;
    if (bio->bi_iter.bi_size > UINT_MAX - len)
        return true;
    return false;
}

/**
 * __bio_add_page - add page(s) to a bio in a new segment
 * @bio: destination bio
 * @page: start page to add
 * @len: length of the data to add, may cross pages
 * @off: offset of the data relative to @page, may cross pages
 *
 * Add the data at @page + @off to @bio as a new bvec.  The caller must ensure
 * that @bio has space for another bvec.
 */
void __bio_add_page(struct bio *bio, struct page *page,
                    unsigned int len, unsigned int off)
{
    struct bio_vec *bv = &bio->bi_io_vec[bio->bi_vcnt];

    WARN_ON_ONCE(bio_flagged(bio, BIO_CLONED));
    WARN_ON_ONCE(bio_full(bio, len));

    bv->bv_page = page;
    bv->bv_offset = off;
    bv->bv_len = len;

    bio->bi_iter.bi_size += len;
    bio->bi_vcnt++;

    if (!bio_flagged(bio, BIO_WORKINGSET) && unlikely(PageWorkingset(page)))
        bio_set_flag(bio, BIO_WORKINGSET);
}
EXPORT_SYMBOL_GPL(__bio_add_page);

/**
 *  bio_add_page    -   attempt to add page(s) to bio
 *  @bio: destination bio
 *  @page: start page to add
 *  @len: vec entry length, may cross pages
 *  @offset: vec entry offset relative to @page, may cross pages
 *
 *  Attempt to add page(s) to the bio_vec maplist. This will only fail
 *  if either bio->bi_vcnt == bio->bi_max_vecs or it's a cloned bio.
 */
int bio_add_page(struct bio *bio, struct page *page,
                 unsigned int len, unsigned int offset)
{
    bool same_page = false;

    if (!__bio_try_merge_page(bio, page, len, offset, &same_page)) {
        if (bio_full(bio, len))
            return 0;
        __bio_add_page(bio, page, len, offset);
    }
    return len;
}
EXPORT_SYMBOL(bio_add_page);

/*
 * bioset_exit - exit a bioset initialized with bioset_init()
 *
 * May be called on a zeroed but uninitialized bioset (i.e. allocated with
 * kzalloc()).
 */
void bioset_exit(struct bio_set *bs)
{
#if 0
    bio_alloc_cache_destroy(bs);
    if (bs->rescue_workqueue)
        destroy_workqueue(bs->rescue_workqueue);
    bs->rescue_workqueue = NULL;

    mempool_exit(&bs->bio_pool);
    mempool_exit(&bs->bvec_pool);

    bioset_integrity_free(bs);
    if (bs->bio_slab)
        bio_put_slab(bs);
    bs->bio_slab = NULL;
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(bioset_exit);

void bio_uninit(struct bio *bio)
{
}
EXPORT_SYMBOL(bio_uninit);

static void bio_free(struct bio *bio)
{
    panic("%s: END!\n", __func__);
}

/**
 * bio_truncate - truncate the bio to small size of @new_size
 * @bio:    the bio to be truncated
 * @new_size:   new size for truncating the bio
 *
 * Description:
 *   Truncate the bio to new size of @new_size. If bio_op(bio) is
 *   REQ_OP_READ, zero the truncated part. This function should only
 *   be used for handling corner cases, such as bio eod.
 */
static void bio_truncate(struct bio *bio, unsigned new_size)
{
    struct bio_vec bv;
    struct bvec_iter iter;
    unsigned int done = 0;
    bool truncated = false;

    if (new_size >= bio->bi_iter.bi_size)
        return;

    panic("%s: END!\n", __func__);
}

/**
 * guard_bio_eod - truncate a BIO to fit the block device
 * @bio:    bio to truncate
 *
 * This allows us to do IO even on the odd last sectors of a device, even if the
 * block size is some multiple of the physical sector size.
 *
 * We'll just truncate the bio to the size of the device, and clear the end of
 * the buffer head manually.  Truly out-of-range accesses will turn into actual
 * I/O errors, this only handles the "we need to be able to do I/O at the final
 * sector" case.
 */
void guard_bio_eod(struct bio *bio)
{
    sector_t maxsector = bdev_nr_sectors(bio->bi_bdev);

    if (!maxsector)
        return;

    /*
     * If the *whole* IO is past the end of the device,
     * let it through, and the IO layer will turn it into
     * an EIO.
     */
    if (unlikely(bio->bi_iter.bi_sector >= maxsector))
        return;

    maxsector -= bio->bi_iter.bi_sector;
    if (likely((bio->bi_iter.bi_size >> 9) <= maxsector))
        return;

    bio_truncate(bio, maxsector << 9);
}

#define ALLOC_CACHE_MAX     512
#define ALLOC_CACHE_SLACK    64

static void bio_alloc_cache_prune(struct bio_alloc_cache *cache,
                                  unsigned int nr)
{
    unsigned int i = 0;
    struct bio *bio;

    while ((bio = cache->free_list) != NULL) {
        cache->free_list = bio->bi_next;
        cache->nr--;
        bio_free(bio);
        if (++i == nr)
            break;
    }
}

/**
 * bio_put - release a reference to a bio
 * @bio:   bio to release reference to
 *
 * Description:
 *   Put a reference to a &struct bio, either one you have gotten with
 *   bio_alloc, bio_get or bio_clone_*. The last put of a bio will free it.
 **/
void bio_put(struct bio *bio)
{
    if (unlikely(bio_flagged(bio, BIO_REFFED))) {
        BUG_ON(!atomic_read(&bio->__bi_cnt));
        if (!atomic_dec_and_test(&bio->__bi_cnt))
            return;
    }

    if (bio_flagged(bio, BIO_PERCPU_CACHE)) {
        struct bio_alloc_cache *cache;

        bio_uninit(bio);
        cache = per_cpu_ptr(bio->bi_pool->cache, get_cpu());
        bio->bi_next = cache->free_list;
        cache->free_list = bio;
        if (++cache->nr > ALLOC_CACHE_MAX + ALLOC_CACHE_SLACK)
            bio_alloc_cache_prune(cache, ALLOC_CACHE_SLACK);
        put_cpu();
    } else {
        bio_free(bio);
    }
}
EXPORT_SYMBOL(bio_put);

/*
 * create memory pools for biovec's in a bio_set.
 * use the global biovec slabs created for general use.
 */
int biovec_init_pool(mempool_t *pool, int pool_entries)
{
    struct biovec_slab *bp = bvec_slabs + ARRAY_SIZE(bvec_slabs) - 1;

    return mempool_init_slab_pool(pool, pool_entries, bp->slab);
}

/**
 * bioset_init - Initialize a bio_set
 * @bs:     pool to initialize
 * @pool_size:  Number of bio and bio_vecs to cache in the mempool
 * @front_pad:  Number of bytes to allocate in front of the returned bio
 * @flags:  Flags to modify behavior, currently %BIOSET_NEED_BVECS
 *              and %BIOSET_NEED_RESCUER
 *
 * Description:
 *    Set up a bio_set to be used with @bio_alloc_bioset. Allows the caller
 *    to ask for a number of bytes to be allocated in front of the bio.
 *    Front pad allocation is useful for embedding the bio inside
 *    another structure, to avoid allocating extra data to go with the bio.
 *    Note that the bio must be embedded at the END of that structure always,
 *    or things will break badly.
 *    If %BIOSET_NEED_BVECS is set in @flags, a separate pool will be allocated
 *    for allocating iovecs.  This pool is not needed e.g. for bio_init_clone().
 *    If %BIOSET_NEED_RESCUER is set, a workqueue is created which can be used
 *    to dispatch queued requests when the mempool runs out of space.
 *
 */
int bioset_init(struct bio_set *bs, unsigned int pool_size,
                unsigned int front_pad, int flags)
{
    bs->front_pad = front_pad;
    if (flags & BIOSET_NEED_BVECS)
        bs->back_pad = BIO_INLINE_VECS * sizeof(struct bio_vec);
    else
        bs->back_pad = 0;

    spin_lock_init(&bs->rescue_lock);
    bio_list_init(&bs->rescue_list);
    //INIT_WORK(&bs->rescue_work, bio_alloc_rescue);

    bs->bio_slab = bio_find_or_create_slab(bs);
    if (!bs->bio_slab)
        return -ENOMEM;

    if (mempool_init_slab_pool(&bs->bio_pool, pool_size, bs->bio_slab))
        goto bad;

    if ((flags & BIOSET_NEED_BVECS) &&
        biovec_init_pool(&bs->bvec_pool, pool_size))
        goto bad;

    if (flags & BIOSET_NEED_RESCUER) {
#if 0
        bs->rescue_workqueue = alloc_workqueue("bioset", WQ_MEM_RECLAIM, 0);
        if (!bs->rescue_workqueue)
            goto bad;
#endif
        panic("%s: BIOSET_NEED_RESCUER!\n", __func__);
    }
    if (flags & BIOSET_PERCPU_CACHE) {
        bs->cache = alloc_percpu(struct bio_alloc_cache);
        if (!bs->cache)
            goto bad;
        //cpuhp_state_add_instance_nocalls(CPUHP_BIO_DEAD, &bs->cpuhp_dead);
    }

    return 0;

 bad:
    bioset_exit(bs);
    return -ENOMEM;
}

static int __init init_bio(void)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(bvec_slabs); i++) {
        struct biovec_slab *bvs = bvec_slabs + i;

        bvs->slab =
            kmem_cache_create(bvs->name,
                              bvs->nr_vecs * sizeof(struct bio_vec), 0,
                              SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);
    }

#if 0
    cpuhp_setup_state_multi(CPUHP_BIO_DEAD, "block/bio:dead", NULL,
                            bio_cpu_dead);
#endif

    if (bioset_init(&fs_bio_set, BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS))
        panic("bio: can't allocate bios\n");

    return 0;
}
subsys_initcall(init_bio);

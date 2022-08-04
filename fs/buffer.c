// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/buffer.c
 *
 *  Copyright (C) 1991, 1992, 2002  Linus Torvalds
 */

/*
 * Start bdflush() with kernel_thread not syscall - Paul Gortmaker, 12/95
 *
 * Removed a lot of unnecessary code and simplified things now that
 * the buffer cache isn't our primary cache - Andrew Tridgell 12/96
 *
 * Speed up hash, lru, and free list operations.  Use gfp() for allocating
 * hash table, use SLAB cache for buffer heads. SMP threading.  -DaveM
 *
 * Added 32k buffer block sizes - these are required older ARM systems. - RMK
 *
 * async buffer flushing, 1999 Andrea Arcangeli <andrea@suse.de>
 */

#include <linux/kernel.h>
#include <linux/sched/signal.h>
//#include <linux/syscalls.h>
#include <linux/fs.h>
//#include <linux/iomap.h>
#include <linux/mm.h>
#include <linux/percpu.h>
#include <linux/slab.h>
//#include <linux/capability.h>
#include <linux/blkdev.h>
//#include <linux/file.h>
//#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/export.h>
#include <linux/backing-dev.h>
#include <linux/writeback.h>
#include <linux/hash.h>
//#include <linux/suspend.h>
#include <linux/buffer_head.h>
//#include <linux/task_io_accounting_ops.h>
#include <linux/bio.h>
#include <linux/cpu.h>
#include <linux/bitops.h>
//#include <linux/mpage.h>
#include <linux/bit_spinlock.h>
#include <linux/pagevec.h>
#include <linux/sched/mm.h>
#include <linux/fscrypt.h>
#include <linux/swap.h>
#include <linux/ratelimit.h>

#include "internal.h"

#define BH_LRU_SIZE 16

struct bh_lru {
    struct buffer_head *bhs[BH_LRU_SIZE];
};

static DEFINE_PER_CPU(struct bh_lru, bh_lrus) = {{ NULL }};

/*
 * Buffer-head allocation
 */
static struct kmem_cache *bh_cachep __read_mostly;

/*
 * Once the number of bh's in the machine exceeds this level, we start
 * stripping them in writeback.
 */
static unsigned long max_buffer_heads;

int buffer_heads_over_limit;

struct bh_accounting {
    int nr;         /* Number of live bh's */
    int ratelimit;      /* Limit cacheline bouncing */
};

static DEFINE_PER_CPU(struct bh_accounting, bh_accounting) = {0, 0};

#define bh_lru_lock()   local_irq_disable()
#define bh_lru_unlock() local_irq_enable()

static inline void check_irqs_on(void)
{
#ifdef irqs_disabled
    BUG_ON(irqs_disabled());
#endif
}

/*
 * Add a page to the dirty page list.
 *
 * It is a sad fact of life that this function is called from several places
 * deeply under spinlocking.  It may not sleep.
 *
 * If the page has buffers, the uptodate buffers are set dirty, to preserve
 * dirty-state coherency between the page and the buffers.  It the page does
 * not have buffers then when they are later attached they will all be set
 * dirty.
 *
 * The buffers are dirtied before the page is dirtied.  There's a small race
 * window in which a writepage caller may see the page cleanness but not the
 * buffer dirtiness.  That's fine.  If this code were to set the page dirty
 * before the buffers, a concurrent writepage caller could clear the page dirty
 * bit, see a bunch of clean buffers and we'd end up with dirty buffers/clean
 * page on the dirty page list.
 *
 * We use private_lock to lock against try_to_free_buffers while using the
 * page's buffer list.  Also use this to protect against clean buffers being
 * added to the page after it was set dirty.
 *
 * FIXME: may need to call ->reservepage here as well.  That's rather up to the
 * address_space though.
 */
bool block_dirty_folio(struct address_space *mapping, struct folio *folio)
{
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(block_dirty_folio);

/**
 * block_invalidate_folio - Invalidate part or all of a buffer-backed folio.
 * @folio: The folio which is affected.
 * @offset: start of the range to invalidate
 * @length: length of the range to invalidate
 *
 * block_invalidate_folio() is called when all or part of the folio has been
 * invalidated by a truncate operation.
 *
 * block_invalidate_folio() does not have to release all buffers, but it must
 * ensure that no dirty buffer is left outside @offset and that no I/O
 * is underway against any of the blocks which are outside the truncation
 * point.  Because the caller is about to free (and possibly reuse) those
 * blocks on-disk.
 */
void block_invalidate_folio(struct folio *folio, size_t offset, size_t length)
{
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(block_invalidate_folio);

/*
 * Returns if the page has dirty or writeback buffers. If all the buffers
 * are unlocked and clean then the PageDirty information is stale. If
 * any of the pages are locked, it is assumed they are locked for IO.
 */
void buffer_check_dirty_writeback(struct page *page,
                                  bool *dirty, bool *writeback)
{
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(buffer_check_dirty_writeback);

/*
 * Size is a power-of-two in the range 512..PAGE_SIZE,
 * and the case we care about most is PAGE_SIZE.
 *
 * So this *could* possibly be written with those
 * constraints in mind (relevant mostly if some
 * architecture has a slow bit-scan instruction)
 */
static inline int block_size_bits(unsigned int blocksize)
{
    return ilog2(blocksize);
}

static void recalc_bh_state(void)
{
    int i;
    int tot = 0;

    if (__this_cpu_inc_return(bh_accounting.ratelimit) - 1 < 4096)
        return;
    __this_cpu_write(bh_accounting.ratelimit, 0);
    for_each_online_cpu(i)
        tot += per_cpu(bh_accounting, i).nr;
    buffer_heads_over_limit = (tot > max_buffer_heads);
}

struct buffer_head *alloc_buffer_head(gfp_t gfp_flags)
{
    struct buffer_head *ret = kmem_cache_zalloc(bh_cachep, gfp_flags);
    if (ret) {
        INIT_LIST_HEAD(&ret->b_assoc_buffers);
        spin_lock_init(&ret->b_uptodate_lock);
        preempt_disable();
        __this_cpu_inc(bh_accounting.nr);
        recalc_bh_state();
        preempt_enable();
    }
    return ret;
}
EXPORT_SYMBOL(alloc_buffer_head);

void free_buffer_head(struct buffer_head *bh)
{
    BUG_ON(!list_empty(&bh->b_assoc_buffers));
    kmem_cache_free(bh_cachep, bh);
    preempt_disable();
    __this_cpu_dec(bh_accounting.nr);
    recalc_bh_state();
    preempt_enable();
}
EXPORT_SYMBOL(free_buffer_head);

void set_bh_page(struct buffer_head *bh,
                 struct page *page, unsigned long offset)
{
    bh->b_page = page;
    BUG_ON(offset >= PAGE_SIZE);
    if (PageHighMem(page))
        /*
         * This catches illegal uses and preserves the offset:
         */
        bh->b_data = (char *)(0 + offset);
    else
        bh->b_data = page_address(page) + offset;
}
EXPORT_SYMBOL(set_bh_page);

/*
 * Create the appropriate buffers when given a page for data area and
 * the size of each buffer.. Use the bh->b_this_page linked list to
 * follow the buffers created.  Return NULL if unable to create more
 * buffers.
 *
 * The retry flag is used to differentiate async IO (paging, swapping)
 * which may not fail from ordinary buffer allocations.
 */
struct buffer_head *
alloc_page_buffers(struct page *page, unsigned long size, bool retry)
{
    struct buffer_head *bh, *head;
    gfp_t gfp = GFP_NOFS | __GFP_ACCOUNT;
    long offset;

    if (retry)
        gfp |= __GFP_NOFAIL;

    head = NULL;
    offset = PAGE_SIZE;
    while ((offset -= size) >= 0) {
        bh = alloc_buffer_head(gfp);
        if (!bh)
            goto no_grow;

        bh->b_this_page = head;
        bh->b_blocknr = -1;
        head = bh;

        bh->b_size = size;

        /* Link the buffer to its page */
        set_bh_page(bh, page, offset);
    }

 out:
    return head;

/*
 * In case anything failed, we just free everything we got.
 */
 no_grow:
    if (head) {
        do {
            bh = head;
            head = head->b_this_page;
            free_buffer_head(bh);
        } while (head);
    }

    goto out;
}

/*
 * We attach and possibly dirty the buffers atomically wrt
 * block_dirty_folio() via private_lock.  try_to_free_buffers
 * is already excluded via the page lock.
 */
void create_empty_buffers(struct page *page,
                          unsigned long blocksize, unsigned long b_state)
{
    struct buffer_head *bh, *head, *tail;

    head = alloc_page_buffers(page, blocksize, true);
    bh = head;
    do {
        bh->b_state |= b_state;
        tail = bh;
        bh = bh->b_this_page;
    } while (bh);
    tail->b_this_page = head;

    spin_lock(&page->mapping->private_lock);
    if (PageUptodate(page) || PageDirty(page)) {
        panic("%s: 1!\n", __func__);
    }
    attach_page_private(page, head);
    spin_unlock(&page->mapping->private_lock);
}
EXPORT_SYMBOL(create_empty_buffers);

static struct buffer_head *
create_page_buffers(struct page *page, struct inode *inode,
                    unsigned int b_state)
{
    BUG_ON(!PageLocked(page));

    if (!page_has_buffers(page))
        create_empty_buffers(page, 1 << READ_ONCE(inode->i_blkbits), b_state);
    return page_buffers(page);
}

void __lock_buffer(struct buffer_head *bh)
{
    wait_on_bit_lock_io(&bh->b_state, BH_Lock, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__lock_buffer);

static void buffer_io_error(struct buffer_head *bh, char *msg)
{
    if (!test_bit(BH_Quiet, &bh->b_state))
        printk_ratelimited(KERN_ERR
            "Buffer I/O error on dev %pg, logical block %llu%s\n",
            bh->b_bdev, (unsigned long long)bh->b_blocknr, msg);
}

void unlock_buffer(struct buffer_head *bh)
{
    clear_bit_unlock(BH_Lock, &bh->b_state);
    smp_mb__after_atomic();
    wake_up_bit(&bh->b_state, BH_Lock);
}
EXPORT_SYMBOL(unlock_buffer);

static void end_buffer_async_read(struct buffer_head *bh, int uptodate)
{
    unsigned long flags;
    struct buffer_head *first;
    struct buffer_head *tmp;
    struct page *page;
    int page_uptodate = 1;

    BUG_ON(!buffer_async_read(bh));

    page = bh->b_page;
    if (uptodate) {
        set_buffer_uptodate(bh);
    } else {
        clear_buffer_uptodate(bh);
        buffer_io_error(bh, ", async page read");
        SetPageError(page);
    }

    /*
     * Be _very_ careful from here on. Bad things can happen if
     * two buffer heads end IO at almost the same time and both
     * decide that the page is now completely done.
     */
    first = page_buffers(page);
    spin_lock_irqsave(&first->b_uptodate_lock, flags);
    clear_buffer_async_read(bh);
    unlock_buffer(bh);
    tmp = bh;
    do {
        if (!buffer_uptodate(tmp))
            page_uptodate = 0;
        if (buffer_async_read(tmp)) {
            BUG_ON(!buffer_locked(tmp));
            goto still_busy;
        }
        tmp = tmp->b_this_page;
    } while (tmp != bh);
    spin_unlock_irqrestore(&first->b_uptodate_lock, flags);

    /*
     * If none of the buffers had errors and they are all
     * uptodate then we can set the page uptodate.
     */
    if (page_uptodate && !PageError(page))
        SetPageUptodate(page);
    unlock_page(page);
    return;

 still_busy:
    spin_unlock_irqrestore(&first->b_uptodate_lock, flags);
    return;
}

/*
 * I/O completion handler for block_read_full_page() - pages
 * which come unlocked at the end of I/O.
 */
static void end_buffer_async_read_io(struct buffer_head *bh, int uptodate)
{
    end_buffer_async_read(bh, uptodate);
}

/*
 * If a page's buffers are under async readin (end_buffer_async_read
 * completion) then there is a possibility that another thread of
 * control could lock one of the buffers after it has completed
 * but while some of the other buffers have not completed.  This
 * locked buffer would confuse end_buffer_async_read() into not unlocking
 * the page.  So the absence of BH_Async_Read tells end_buffer_async_read()
 * that this buffer is not under async I/O.
 *
 * The page comes unlocked when it has no locked buffer_async buffers
 * left.
 *
 * PageLocked prevents anyone starting new async I/O reads any of
 * the buffers.
 *
 * PageWriteback is used to prevent simultaneous writeout of the same
 * page.
 *
 * PageLocked prevents anyone from starting writeback of a page which is
 * under read I/O (PageWriteback is only ever set against a locked page).
 */
static void mark_buffer_async_read(struct buffer_head *bh)
{
    bh->b_end_io = end_buffer_async_read_io;
    set_buffer_async_read(bh);
}

static void end_bio_bh_io_sync(struct bio *bio)
{
    struct buffer_head *bh = bio->bi_private;

    if (unlikely(bio_flagged(bio, BIO_QUIET)))
        set_bit(BH_Quiet, &bh->b_state);

    bh->b_end_io(bh, !bio->bi_status);
    bio_put(bio);
}

static int submit_bh_wbc(int op, int op_flags, struct buffer_head *bh,
                         struct writeback_control *wbc)
{
    struct bio *bio;

    BUG_ON(!buffer_locked(bh));
    BUG_ON(!buffer_mapped(bh));
    BUG_ON(!bh->b_end_io);
    BUG_ON(buffer_delay(bh));
    BUG_ON(buffer_unwritten(bh));

    /*
     * Only clear out a write error when rewriting
     */
    if (test_set_buffer_req(bh) && (op == REQ_OP_WRITE))
        clear_buffer_write_io_error(bh);

    if (buffer_meta(bh))
        op_flags |= REQ_META;
    if (buffer_prio(bh))
        op_flags |= REQ_PRIO;

    bio = bio_alloc(bh->b_bdev, 1, op | op_flags, GFP_NOIO);

    bio->bi_iter.bi_sector = bh->b_blocknr * (bh->b_size >> 9);

    bio_add_page(bio, bh->b_page, bh->b_size, bh_offset(bh));
    BUG_ON(bio->bi_iter.bi_size != bh->b_size);

    bio->bi_end_io = end_bio_bh_io_sync;
    bio->bi_private = bh;

    /* Take care of bh's that straddle the end of the device */
    guard_bio_eod(bio);

    if (wbc) {
        panic("%s: wbc!\n", __func__);
    }

    submit_bio(bio);
    return 0;
}

int submit_bh(int op, int op_flags, struct buffer_head *bh)
{
    return submit_bh_wbc(op, op_flags, bh, NULL);
}
EXPORT_SYMBOL(submit_bh);

/*
 * Generic "read page" function for block devices that have the normal
 * get_block functionality. This is most of the block device filesystems.
 * Reads the page asynchronously --- the unlock_buffer() and
 * set/clear_buffer_uptodate() functions propagate buffer state into the
 * page struct once IO has completed.
 */
int block_read_full_page(struct page *page, get_block_t *get_block)
{
    struct inode *inode = page->mapping->host;
    sector_t iblock, lblock;
    struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
    unsigned int blocksize, bbits;
    int nr, i;
    int fully_mapped = 1;

    head = create_page_buffers(page, inode, 0);
    blocksize = head->b_size;
    bbits = block_size_bits(blocksize);

    iblock = (sector_t)page->index << (PAGE_SHIFT - bbits);
    lblock = (i_size_read(inode)+blocksize-1) >> bbits;
    bh = head;
    nr = 0;
    i = 0;

    do {
        if (buffer_uptodate(bh))
            continue;

        if (!buffer_mapped(bh)) {
            int err = 0;

            fully_mapped = 0;
            if (iblock < lblock) {
                WARN_ON(bh->b_size != blocksize);
                err = get_block(inode, iblock, bh, 0);
                if (err)
                    SetPageError(page);
            }
            if (!buffer_mapped(bh)) {
                zero_user(page, i * blocksize, blocksize);
                if (!err)
                    set_buffer_uptodate(bh);
                continue;
            }
            /*
             * get_block() might have updated the buffer
             * synchronously
             */
            if (buffer_uptodate(bh))
                continue;
        }
        arr[nr++] = bh;
    } while (i++, iblock++, (bh = bh->b_this_page) != head);

    if (fully_mapped)
        SetPageMappedToDisk(page);

    if (!nr) {
        /*
         * All buffers are uptodate - we can set the page uptodate
         * as well. But not if get_block() returned an error.
         */
        if (!PageError(page))
            SetPageUptodate(page);
        unlock_page(page);
        return 0;
    }

    /* Stage two: lock the buffers */
    for (i = 0; i < nr; i++) {
        bh = arr[i];
        lock_buffer(bh);
        mark_buffer_async_read(bh);
    }

    /*
     * Stage 3: start the IO.  Check for uptodateness
     * inside the buffer lock in case another process reading
     * the underlying blockdev brought it uptodate (the sct fix).
     */
    for (i = 0; i < nr; i++) {
        bh = arr[i];
        if (buffer_uptodate(bh))
            end_buffer_async_read(bh, 1);
        else
            submit_bh(REQ_OP_READ, 0, bh);
    }
    return 0;
}
EXPORT_SYMBOL(block_read_full_page);

static int buffer_exit_cpu_dead(unsigned int cpu)
{
#if 0
    int i;
    struct bh_lru *b = &per_cpu(bh_lrus, cpu);

    for (i = 0; i < BH_LRU_SIZE; i++) {
        brelse(b->bhs[i]);
        b->bhs[i] = NULL;
    }
    this_cpu_add(bh_accounting.nr, per_cpu(bh_accounting, cpu).nr);
    per_cpu(bh_accounting, cpu).nr = 0;
#endif
    panic("%s: END!\n", __func__);
    return 0;
}

/*
 * invalidate_bh_lrus() is called rarely - but not only at unmount.
 * This doesn't race because it runs in each cpu either in irq
 * or with preempt disabled.
 */
static void invalidate_bh_lru(void *arg)
{
#if 0
    struct bh_lru *b = &get_cpu_var(bh_lrus);

    __invalidate_bh_lrus(b);
    put_cpu_var(bh_lrus);
#endif
    panic("%s: END!\n", __func__);
}

bool has_bh_in_lru(int cpu, void *dummy)
{
    struct bh_lru *b = per_cpu_ptr(&bh_lrus, cpu);
    int i;

    for (i = 0; i < BH_LRU_SIZE; i++) {
        if (b->bhs[i])
            return true;
    }

    return false;
}

void invalidate_bh_lrus(void)
{
    on_each_cpu_cond(has_bh_in_lru, invalidate_bh_lru, NULL, 1);
}
EXPORT_SYMBOL_GPL(invalidate_bh_lrus);

/*
 * Look up the bh in this cpu's LRU.  If it's there, move it to the head.
 */
static struct buffer_head *
lookup_bh_lru(struct block_device *bdev, sector_t block, unsigned size)
{
    struct buffer_head *ret = NULL;
    unsigned int i;

    check_irqs_on();
    bh_lru_lock();
    for (i = 0; i < BH_LRU_SIZE; i++) {
        struct buffer_head *bh = __this_cpu_read(bh_lrus.bhs[i]);

        if (bh && bh->b_blocknr == block &&
            bh->b_bdev == bdev &&
            bh->b_size == size) {
            if (i) {
                while (i) {
                    __this_cpu_write(bh_lrus.bhs[i],
                                     __this_cpu_read(bh_lrus.bhs[i - 1]));
                    i--;
                }
                __this_cpu_write(bh_lrus.bhs[0], bh);
            }
            get_bh(bh);
            ret = bh;
            break;
        }
    }
    bh_lru_unlock();
    return ret;
}

inline void touch_buffer(struct buffer_head *bh)
{
    mark_page_accessed(bh->b_page);
}
EXPORT_SYMBOL(touch_buffer);

/*
 * Various filesystems appear to want __find_get_block to be non-blocking.
 * But it's the page lock which protects the buffers.  To get around this,
 * we get exclusion from try_to_free_buffers with the blockdev mapping's
 * private_lock.
 *
 * Hack idea: for the blockdev mapping, private_lock contention
 * may be quite high.  This code could TryLock the page, and if that
 * succeeds, there is no need to take private_lock.
 */
static struct buffer_head *
__find_get_block_slow(struct block_device *bdev, sector_t block)
{
    struct inode *bd_inode = bdev->bd_inode;
    struct address_space *bd_mapping = bd_inode->i_mapping;
    struct buffer_head *ret = NULL;
    pgoff_t index;
    struct buffer_head *bh;
    struct buffer_head *head;
    struct page *page;
    int all_mapped = 1;
    static DEFINE_RATELIMIT_STATE(last_warned, HZ, 1);

    index = block >> (PAGE_SHIFT - bd_inode->i_blkbits);
    page = find_get_page_flags(bd_mapping, index, FGP_ACCESSED);
    if (!page)
        goto out;

    spin_lock(&bd_mapping->private_lock);
    if (!page_has_buffers(page))
        goto out_unlock;
    head = page_buffers(page);
    bh = head;
    do {
        if (!buffer_mapped(bh))
            all_mapped = 0;
        else if (bh->b_blocknr == block) {
            ret = bh;
            get_bh(bh);
            goto out_unlock;
        }
        bh = bh->b_this_page;
    } while (bh != head);

    /* we might be here because some of the buffers on this page are
     * not mapped.  This is due to various races between
     * file io on the block device and getblk.  It gets dealt with
     * elsewhere, don't buffer_error if we had some unmapped buffers
     */
    ratelimit_set_flags(&last_warned, RATELIMIT_MSG_ON_RELEASE);
#if 0
    if (all_mapped && __ratelimit(&last_warned)) {
        printk("__find_get_block_slow() failed. block=%llu, "
               "b_blocknr=%llu, b_state=0x%08lx, b_size=%zu, "
               "device %pg blocksize: %d\n",
               (unsigned long long)block,
               (unsigned long long)bh->b_blocknr,
               bh->b_state, bh->b_size, bdev,
               1 << bd_inode->i_blkbits);
    }
#endif
 out_unlock:
    spin_unlock(&bd_mapping->private_lock);
    put_page(page);
 out:
    return ret;
}

/*
 * Install a buffer_head into this cpu's LRU.  If not already in the LRU, it is
 * inserted at the front, and the buffer_head at the back if any is evicted.
 * Or, if already in the LRU it is moved to the front.
 */
static void bh_lru_install(struct buffer_head *bh)
{
    struct buffer_head *evictee = bh;
    struct bh_lru *b;
    int i;

    check_irqs_on();
    bh_lru_lock();

    /*
     * the refcount of buffer_head in bh_lru prevents dropping the
     * attached page(i.e., try_to_free_buffers) so it could cause
     * failing page migration.
     * Skip putting upcoming bh into bh_lru until migration is done.
     */
    if (lru_cache_disabled()) {
        bh_lru_unlock();
        return;
    }

    b = this_cpu_ptr(&bh_lrus);
    for (i = 0; i < BH_LRU_SIZE; i++) {
        swap(evictee, b->bhs[i]);
        if (evictee == bh) {
            bh_lru_unlock();
            return;
        }
    }

    get_bh(bh);
    bh_lru_unlock();
    brelse(evictee);
}

/*
 * Perform a pagecache lookup for the matching buffer.  If it's there, refresh
 * it in the LRU and mark it as accessed.  If it is not present then return
 * NULL
 */
struct buffer_head *
__find_get_block(struct block_device *bdev, sector_t block, unsigned size)
{
    struct buffer_head *bh = lookup_bh_lru(bdev, block, size);

    if (bh == NULL) {
        /* __find_get_block_slow will mark the page accessed */
        bh = __find_get_block_slow(bdev, block);
        if (bh)
            bh_lru_install(bh);
    } else
        touch_buffer(bh);

    return bh;
}
EXPORT_SYMBOL(__find_get_block);

static sector_t blkdev_max_block(struct block_device *bdev, unsigned int size)
{
    sector_t retval = ~((sector_t)0);
    loff_t sz = bdev_nr_bytes(bdev);

    if (sz) {
        unsigned int sizebits = blksize_bits(size);
        retval = (sz >> sizebits);
    }
    return retval;
}

/*
 * Initialise the state of a blockdev page's buffers.
 */
static sector_t
init_page_buffers(struct page *page, struct block_device *bdev,
                  sector_t block, int size)
{
    struct buffer_head *head = page_buffers(page);
    struct buffer_head *bh = head;
    int uptodate = PageUptodate(page);
    sector_t end_block = blkdev_max_block(bdev, size);

    do {
        if (!buffer_mapped(bh)) {
            bh->b_end_io = NULL;
            bh->b_private = NULL;
            bh->b_bdev = bdev;
            bh->b_blocknr = block;
            if (uptodate)
                set_buffer_uptodate(bh);
            if (block < end_block)
                set_buffer_mapped(bh);
        }
        block++;
        bh = bh->b_this_page;
    } while (bh != head);

    /*
     * Caller needs to validate requested block against end of device.
     */
    return end_block;
}

/*
 * try_to_free_buffers() checks if all the buffers on this particular page
 * are unused, and releases them if so.
 *
 * Exclusion against try_to_free_buffers may be obtained by either
 * locking the page or by holding its mapping's private_lock.
 *
 * If the page is dirty but all the buffers are clean then we need to
 * be sure to mark the page clean as well.  This is because the page
 * may be against a block device, and a later reattachment of buffers
 * to a dirty page will set *all* buffers dirty.  Which would corrupt
 * filesystem data on the same device.
 *
 * The same applies to regular filesystem pages: if all the buffers are
 * clean then we set the page clean and proceed.  To do that, we require
 * total exclusion from block_dirty_folio().  That is obtained with
 * private_lock.
 *
 * try_to_free_buffers() is non-blocking.
 */
static inline int buffer_busy(struct buffer_head *bh)
{
    return atomic_read(&bh->b_count) |
        (bh->b_state & ((1 << BH_Dirty) | (1 << BH_Lock)));
}

/*
 * The buffer's backing address_space's private_lock must be held
 */
static void __remove_assoc_queue(struct buffer_head *bh)
{
    list_del_init(&bh->b_assoc_buffers);
    WARN_ON(!bh->b_assoc_map);
    bh->b_assoc_map = NULL;
}

static int
drop_buffers(struct page *page, struct buffer_head **buffers_to_free)
{
    struct buffer_head *head = page_buffers(page);
    struct buffer_head *bh;

    bh = head;
    do {
        if (buffer_busy(bh))
            goto failed;
        bh = bh->b_this_page;
    } while (bh != head);

    do {
        struct buffer_head *next = bh->b_this_page;

        if (bh->b_assoc_map)
            __remove_assoc_queue(bh);
        bh = next;
    } while (bh != head);
    *buffers_to_free = head;
    detach_page_private(page);
    return 1;
failed:
    return 0;
}

int try_to_free_buffers(struct page *page)
{
    struct address_space * const mapping = page->mapping;
    struct buffer_head *buffers_to_free = NULL;
    int ret = 0;

    BUG_ON(!PageLocked(page));
    if (PageWriteback(page))
        return 0;

    if (mapping == NULL) {      /* can this still happen? */
        ret = drop_buffers(page, &buffers_to_free);
        goto out;
    }

    spin_lock(&mapping->private_lock);
    ret = drop_buffers(page, &buffers_to_free);

    /*
     * If the filesystem writes its buffers by hand (eg ext3)
     * then we can have clean buffers against a dirty page.  We
     * clean the page here; otherwise the VM will never notice
     * that the filesystem did any IO at all.
     *
     * Also, during truncate, discard_buffer will have marked all
     * the page's buffers clean.  We discover that here and clean
     * the page also.
     *
     * private_lock must be held over this entire operation in order
     * to synchronise against block_dirty_folio and prevent the
     * dirty bit from being lost.
     */
    if (ret)
        cancel_dirty_page(page);
    spin_unlock(&mapping->private_lock);
 out:
    if (buffers_to_free) {
        struct buffer_head *bh = buffers_to_free;

        do {
            struct buffer_head *next = bh->b_this_page;
            free_buffer_head(bh);
            bh = next;
        } while (bh != buffers_to_free);
    }
    return ret;
}

static inline void
link_dev_buffers(struct page *page, struct buffer_head *head)
{
    struct buffer_head *bh, *tail;

    bh = head;
    do {
        tail = bh;
        bh = bh->b_this_page;
    } while (bh);
    tail->b_this_page = head;
    attach_page_private(page, head);
}

/*
 * Create the page-cache page that contains the requested block.
 *
 * This is used purely for blockdev mappings.
 */
static int
grow_dev_page(struct block_device *bdev, sector_t block,
              pgoff_t index, int size, int sizebits, gfp_t gfp)
{
    struct inode *inode = bdev->bd_inode;
    struct page *page;
    struct buffer_head *bh;
    sector_t end_block;
    int ret = 0;
    gfp_t gfp_mask;

    gfp_mask = mapping_gfp_constraint(inode->i_mapping, ~__GFP_FS) | gfp;

    /*
     * XXX: __getblk_slow() can not really deal with failure and
     * will endlessly loop on improvised global reclaim.  Prefer
     * looping in the allocator rather than here, at least that
     * code knows what it's doing.
     */
    gfp_mask |= __GFP_NOFAIL;

    page = find_or_create_page(inode->i_mapping, index, gfp_mask);

    BUG_ON(!PageLocked(page));

    if (page_has_buffers(page)) {
        bh = page_buffers(page);
        if (bh->b_size == size) {
            end_block = init_page_buffers(page, bdev,
                                          (sector_t)index << sizebits, size);
            goto done;
        }
        if (!try_to_free_buffers(page))
            goto failed;
    }

    /*
     * Allocate some buffers for this page
     */
    bh = alloc_page_buffers(page, size, true);

    /*
     * Link the page to the buffers and initialise them.  Take the
     * lock to be atomic wrt __find_get_block(), which does not
     * run under the page lock.
     */
    spin_lock(&inode->i_mapping->private_lock);
    link_dev_buffers(page, bh);
    end_block = init_page_buffers(page, bdev,
                                  (sector_t)index << sizebits, size);
    spin_unlock(&inode->i_mapping->private_lock);
 done:
    ret = (block < end_block) ? 1 : -ENXIO;
 failed:
    unlock_page(page);
    put_page(page);
    return ret;
}

/*
 * Create buffers for the specified block device block's page.  If
 * that page was dirty, the buffers are set dirty also.
 */
static int
grow_buffers(struct block_device *bdev, sector_t block, int size, gfp_t gfp)
{
    pgoff_t index;
    int sizebits;

    sizebits = PAGE_SHIFT - __ffs(size);
    index = block >> sizebits;

    /*
     * Check for a block which wants to lie outside our maximum possible
     * pagecache index.  (this comparison is done using sector_t types).
     */
    if (unlikely(index != block >> sizebits)) {
        printk(KERN_ERR "%s: requested out-of-range block %llu for "
               "device %pg\n",
               __func__, (unsigned long long)block, bdev);
        return -EIO;
    }

    /* Create a page with the proper size buffers.. */
    return grow_dev_page(bdev, block, index, size, sizebits, gfp);
}

static struct buffer_head *
__getblk_slow(struct block_device *bdev, sector_t block,
              unsigned size, gfp_t gfp)
{
    /* Size must be multiple of hard sectorsize */
    if (unlikely(size & (bdev_logical_block_size(bdev)-1) ||
            (size < 512 || size > PAGE_SIZE))) {
        printk(KERN_ERR "getblk(): invalid block size %d requested\n",
                    size);
        printk(KERN_ERR "logical block size: %d\n",
                    bdev_logical_block_size(bdev));

        //dump_stack();
        return NULL;
    }

    for (;;) {
        struct buffer_head *bh;
        int ret;

        bh = __find_get_block(bdev, block, size);
        if (bh)
            return bh;

        ret = grow_buffers(bdev, block, size, gfp);
        if (ret < 0)
            return NULL;
    }
}

/*
 * __getblk_gfp() will locate (and, if necessary, create) the buffer_head
 * which corresponds to the passed block_device, block and size. The
 * returned buffer has its reference count incremented.
 *
 * __getblk_gfp() will lock up the machine if grow_dev_page's
 * try_to_free_buffers() attempt is failing.  FIXME, perhaps?
 */
struct buffer_head *
__getblk_gfp(struct block_device *bdev, sector_t block,
             unsigned size, gfp_t gfp)
{
    struct buffer_head *bh = __find_get_block(bdev, block, size);

    might_sleep();
    if (bh == NULL)
        bh = __getblk_slow(bdev, block, size, gfp);
    return bh;
}
EXPORT_SYMBOL(__getblk_gfp);

/*
 * End-of-IO handler helper function which does not touch the bh after
 * unlocking it.
 * Note: unlock_buffer() sort-of does touch the bh after unlocking it, but
 * a race there is benign: unlock_buffer() only use the bh's address for
 * hashing after unlocking the buffer, so it doesn't actually touch the bh
 * itself.
 */
static void __end_buffer_read_notouch(struct buffer_head *bh, int uptodate)
{
    if (uptodate) {
        set_buffer_uptodate(bh);
    } else {
        /* This happens, due to failed read-ahead attempts. */
        clear_buffer_uptodate(bh);
    }
    unlock_buffer(bh);
}

/*
 * Default synchronous end-of-IO handler..  Just mark it up-to-date and
 * unlock the buffer. This is what ll_rw_block uses too.
 */
void end_buffer_read_sync(struct buffer_head *bh, int uptodate)
{
    __end_buffer_read_notouch(bh, uptodate);
    put_bh(bh);
}
EXPORT_SYMBOL(end_buffer_read_sync);

static struct buffer_head *__bread_slow(struct buffer_head *bh)
{
    lock_buffer(bh);
    if (buffer_uptodate(bh)) {
        unlock_buffer(bh);
        return bh;
    } else {
        get_bh(bh);
        bh->b_end_io = end_buffer_read_sync;
        submit_bh(REQ_OP_READ, 0, bh);
        wait_on_buffer(bh);
        if (buffer_uptodate(bh))
            return bh;
    }
    brelse(bh);
    return NULL;
}

/**
 *  __bread_gfp() - reads a specified block and returns the bh
 *  @bdev: the block_device to read from
 *  @block: number of block
 *  @size: size (in bytes) to read
 *  @gfp: page allocation flag
 *
 *  Reads a specified block, and returns buffer head that contains it.
 *  The page cache can be allocated from non-movable area
 *  not to prevent page migration if you set gfp to zero.
 *  It returns NULL if the block was unreadable.
 */
struct buffer_head *
__bread_gfp(struct block_device *bdev, sector_t block, unsigned size, gfp_t gfp)
{
    struct buffer_head *bh = __getblk_gfp(bdev, block, size, gfp);

    if (likely(bh) && !buffer_uptodate(bh))
        bh = __bread_slow(bh);
    return bh;
}
EXPORT_SYMBOL(__bread_gfp);

void __init buffer_init(void)
{
    unsigned long nrpages;
    int ret;

    bh_cachep =
        kmem_cache_create("buffer_head",
                          sizeof(struct buffer_head),
                          0, (SLAB_RECLAIM_ACCOUNT|SLAB_PANIC| SLAB_MEM_SPREAD),
                          NULL);

    /*
     * Limit the bh occupancy to 10% of ZONE_NORMAL
     */
    nrpages = (nr_free_buffer_pages() * 10) / 100;
    max_buffer_heads = nrpages * (PAGE_SIZE / sizeof(struct buffer_head));
#if 0
    ret = cpuhp_setup_state_nocalls(CPUHP_FS_BUFF_DEAD, "fs/buffer:dead",
                                    NULL, buffer_exit_cpu_dead);
    WARN_ON(ret < 0);
#endif
}

/*
 * Decrement a buffer_head's reference count.  If all buffers against a page
 * have zero reference count, are clean and unlocked, and if the page is clean
 * and unlocked then try_to_free_buffers() may strip the buffers from the page
 * in preparation for freeing it (sometimes, rarely, buffers are removed from
 * a page but it ends up not being freed, and buffers may later be reattached).
 */
void __brelse(struct buffer_head * buf)
{
    if (atomic_read(&buf->b_count)) {
        put_bh(buf);
        return;
    }
    WARN(1, KERN_ERR "VFS: brelse: Trying to free free buffer\n");
}
EXPORT_SYMBOL(__brelse);

/*
 * Block until a buffer comes unlocked.  This doesn't stop it
 * from becoming locked again - you have to lock it yourself
 * if you want to preserve its state.
 */
void __wait_on_buffer(struct buffer_head * bh)
{
    wait_on_bit_io(&bh->b_state, BH_Lock, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(__wait_on_buffer);

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

#include "internal.h"

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

static void end_buffer_async_read(struct buffer_head *bh, int uptodate)
{
    panic("%s: END!\n", __func__);
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

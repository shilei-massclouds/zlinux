// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/filemap.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * This file handles the generic file mmap semantics used by
 * most "normal" filesystems (but you don't /have/ to use this:
 * the NFS filesystem used to do this differently, for example)
 */
#include <linux/export.h>
#include <linux/compiler.h>
//#include <linux/dax.h>
#include <linux/fs.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
//#include <linux/capability.h>
#include <linux/kernel_stat.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/swapops.h>
#include <linux/mman.h>
#include <linux/file.h>
#if 0
#include <linux/error-injection.h>
#endif
#include <linux/uio.h>
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#include <linux/pagevec.h>
#include <linux/security.h>
#if 0
#include <linux/cpuset.h>
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/delayacct.h>
#include <linux/psi.h>
#endif
#include <linux/rmap.h>
#include <linux/page_idle.h>
#include <linux/shmem_fs.h>
#include <linux/ramfs.h>
#if 0
#include <linux/migrate.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#endif
#include "internal.h"

/*
 * FIXME: remove all knowledge of the buffer layer from the core VM
 */
#include <linux/buffer_head.h> /* for try_to_free_buffers */

#include <asm/mman.h>

#define MMAP_LOTSAMISS  (100)

/*
 * A choice of three behaviors for folio_wait_bit_common():
 */
enum behavior {
    EXCLUSIVE,  /* Hold ref to page and take the bit when woken, like
                 * __folio_lock() waiting on then setting PG_locked.
                 */
    SHARED,     /* Hold ref to page and check the bit when woken, like
                 * folio_wait_writeback() waiting on PG_writeback.
                 */
    DROP,       /* Drop ref to page before wait, no check when woken,
                 * like folio_put_wait_locked() on PG_locked.
                 */
};

static inline int
folio_wait_bit_common(struct folio *folio, int bit_nr,
                      int state, enum behavior behavior);

/*
 * In order to wait for pages to become available there must be
 * waitqueues associated with pages. By using a hash table of
 * waitqueues where the bucket discipline is to maintain all
 * waiters on the same queue and wake all when any of the pages
 * become available, and for the woken contexts to check to be
 * sure the appropriate page became available, this saves space
 * at a cost of "thundering herd" phenomena during rare hash
 * collisions.
 */
#define PAGE_WAIT_TABLE_BITS 8
#define PAGE_WAIT_TABLE_SIZE (1 << PAGE_WAIT_TABLE_BITS)
static wait_queue_head_t folio_wait_table[PAGE_WAIT_TABLE_SIZE]
    __cacheline_aligned;

static wait_queue_head_t *folio_waitqueue(struct folio *folio)
{
    return &folio_wait_table[hash_ptr(folio, PAGE_WAIT_TABLE_BITS)];
}

static struct folio *next_uptodate_page(struct folio *folio,
                                        struct address_space *mapping,
                                        struct xa_state *xas,
                                        pgoff_t end_pgoff)
{
    unsigned long max_idx;

    do {
        if (!folio)
            return NULL;
        if (xas_retry(xas, folio))
            continue;
        if (xa_is_value(folio))
            continue;
        if (folio_test_locked(folio))
            continue;
        if (!folio_try_get_rcu(folio))
            continue;
        /* Has the page moved or been split? */
        if (unlikely(folio != xas_reload(xas)))
            goto skip;
        if (!folio_test_uptodate(folio) || folio_test_readahead(folio))
            goto skip;
        if (!folio_trylock(folio))
            goto skip;
        if (folio->mapping != mapping)
            goto unlock;
        if (!folio_test_uptodate(folio))
            goto unlock;
        max_idx = DIV_ROUND_UP(i_size_read(mapping->host), PAGE_SIZE);
        if (xas->xa_index >= max_idx)
            goto unlock;
        return folio;
unlock:
        folio_unlock(folio);
skip:
        folio_put(folio);
    } while ((folio = xas_next_entry(xas, end_pgoff)) != NULL);

    return NULL;
}

static inline struct folio *
first_map_page(struct address_space *mapping, struct xa_state *xas,
               pgoff_t end_pgoff)
{
    return next_uptodate_page(xas_find(xas, end_pgoff),
                              mapping, xas, end_pgoff);
}

static inline struct folio *
next_map_page(struct address_space *mapping, struct xa_state *xas,
              pgoff_t end_pgoff)
{
    return next_uptodate_page(xas_next_entry(xas, end_pgoff),
                              mapping, xas, end_pgoff);
}

static inline
bool folio_more_pages(struct folio *folio, pgoff_t index, pgoff_t max)
{
    if (!folio_test_large(folio) || folio_test_hugetlb(folio))
        return false;
    if (index >= max)
        return false;
    return index < folio->index + folio_nr_pages(folio) - 1;
}

static bool filemap_map_pmd(struct vm_fault *vmf, struct page *page)
{
    struct mm_struct *mm = vmf->vma->vm_mm;

    /* Huge page is mapped? No need to proceed. */
    if (pmd_trans_huge(*vmf->pmd)) {
        unlock_page(page);
        put_page(page);
        return true;
    }

    if (pmd_none(*vmf->pmd) && PageTransHuge(page)) {
        vm_fault_t ret = do_set_pmd(vmf, page);
        if (!ret) {
            /* The page is mapped successfully, reference consumed. */
            unlock_page(page);
            return true;
        }
    }

    if (pmd_none(*vmf->pmd))
        pmd_install(mm, vmf->pmd, &vmf->prealloc_pte);

    /* See comment in handle_pte_fault() */
    if (pmd_devmap_trans_unstable(vmf->pmd)) {
        unlock_page(page);
        put_page(page);
        return true;
    }

    return false;
}

vm_fault_t filemap_map_pages(struct vm_fault *vmf,
                             pgoff_t start_pgoff, pgoff_t end_pgoff)
{
    struct vm_area_struct *vma = vmf->vma;
    struct file *file = vma->vm_file;
    struct address_space *mapping = file->f_mapping;
    pgoff_t last_pgoff = start_pgoff;
    unsigned long addr;
    XA_STATE(xas, &mapping->i_pages, start_pgoff);
    struct folio *folio;
    struct page *page;
    unsigned int mmap_miss = READ_ONCE(file->f_ra.mmap_miss);
    vm_fault_t ret = 0;

    rcu_read_lock();
    folio = first_map_page(mapping, &xas, end_pgoff);
    if (!folio)
        goto out;

    if (filemap_map_pmd(vmf, &folio->page)) {
        ret = VM_FAULT_NOPAGE;
        goto out;
    }

    addr = vma->vm_start + ((start_pgoff - vma->vm_pgoff) << PAGE_SHIFT);
    vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, addr, &vmf->ptl);

    do {
     again:
        page = folio_file_page(folio, xas.xa_index);
        if (PageHWPoison(page))
            goto unlock;

        if (mmap_miss > 0)
            mmap_miss--;

        addr += (xas.xa_index - last_pgoff) << PAGE_SHIFT;
        vmf->pte += xas.xa_index - last_pgoff;
        last_pgoff = xas.xa_index;

        if (!pte_none(*vmf->pte))
            goto unlock;

        /* We're about to handle the fault */
        if (vmf->address == addr)
            ret = VM_FAULT_NOPAGE;

        do_set_pte(vmf, page, addr);
        /* no need to invalidate: a not-present page won't be cached */
        update_mmu_cache(vma, addr, vmf->pte);
        if (folio_more_pages(folio, xas.xa_index, end_pgoff)) {
            xas.xa_index++;
            folio_ref_inc(folio);
            goto again;
        }
        folio_unlock(folio);
        continue;
     unlock:
        if (folio_more_pages(folio, xas.xa_index, end_pgoff)) {
            xas.xa_index++;
            goto again;
        }
        folio_unlock(folio);
        folio_put(folio);
    } while ((folio = next_map_page(mapping, &xas, end_pgoff)) != NULL);
    pte_unmap_unlock(vmf->pte, vmf->ptl);
 out:
    rcu_read_unlock();
    WRITE_ONCE(file->f_ra.mmap_miss, mmap_miss);
    return ret;
}
EXPORT_SYMBOL(filemap_map_pages);

/*
 * Synchronous readahead happens when we don't even find a page in the page
 * cache at all.  We don't want to perform IO under the mmap sem, so if we have
 * to drop the mmap sem we return the file that was pinned in order for us to do
 * that.  If we didn't pin a file then we return NULL.  The file that is
 * returned needs to be fput()'ed when we're done with it.
 */
static struct file *do_sync_mmap_readahead(struct vm_fault *vmf)
{
    struct file *file = vmf->vma->vm_file;
    struct file_ra_state *ra = &file->f_ra;
    struct address_space *mapping = file->f_mapping;
    DEFINE_READAHEAD(ractl, file, ra, mapping, vmf->pgoff);
    struct file *fpin = NULL;
    unsigned int mmap_miss;

    /* If we don't want any read-ahead, don't bother */
    if (vmf->vma->vm_flags & VM_RAND_READ)
        return fpin;
    if (!ra->ra_pages)
        return fpin;

    if (vmf->vma->vm_flags & VM_SEQ_READ) {
        fpin = maybe_unlock_mmap_for_io(vmf, fpin);
        page_cache_sync_ra(&ractl, ra->ra_pages);
        return fpin;
    }

    /* Avoid banging the cache line if not needed */
    mmap_miss = READ_ONCE(ra->mmap_miss);
    if (mmap_miss < MMAP_LOTSAMISS * 10)
        WRITE_ONCE(ra->mmap_miss, ++mmap_miss);

    /*
     * Do we miss much more than hit in this file? If so,
     * stop bothering with read-ahead. It will only hurt.
     */
    if (mmap_miss > MMAP_LOTSAMISS)
        return fpin;

    /*
     * mmap read-around
     */
    fpin = maybe_unlock_mmap_for_io(vmf, fpin);
    ra->start = max_t(long, 0, vmf->pgoff - ra->ra_pages / 2);
    ra->size = ra->ra_pages;
    ra->async_size = ra->ra_pages / 4;
    ractl._index = ra->start;
    page_cache_ra_order(&ractl, ra, 0);
    printk("%s: END!\n", __func__);
    return fpin;
}

int __folio_lock_killable(struct folio *folio)
{
    return folio_wait_bit_common(folio, PG_locked, TASK_KILLABLE, EXCLUSIVE);
}
EXPORT_SYMBOL_GPL(__folio_lock_killable);

/*
 * lock_folio_maybe_drop_mmap - lock the page, possibly dropping the mmap_lock
 * @vmf - the vm_fault for this fault.
 * @folio - the folio to lock.
 * @fpin - the pointer to the file we may pin (or is already pinned).
 *
 * This works similar to lock_folio_or_retry in that it can drop the
 * mmap_lock.  It differs in that it actually returns the folio locked
 * if it returns 1 and 0 if it couldn't lock the folio.  If we did have
 * to drop the mmap_lock then fpin will point to the pinned file and
 * needs to be fput()'ed at a later point.
 */
static int lock_folio_maybe_drop_mmap(struct vm_fault *vmf, struct folio *folio,
                                      struct file **fpin)
{
    if (folio_trylock(folio))
        return 1;

    /*
     * NOTE! This will make us return with VM_FAULT_RETRY, but with
     * the mmap_lock still held. That's how FAULT_FLAG_RETRY_NOWAIT
     * is supposed to work. We have way too many special cases..
     */
    if (vmf->flags & FAULT_FLAG_RETRY_NOWAIT)
        return 0;

    *fpin = maybe_unlock_mmap_for_io(vmf, *fpin);
    if (vmf->flags & FAULT_FLAG_KILLABLE) {
        if (__folio_lock_killable(folio)) {
            /*
             * We didn't have the right flags to drop the mmap_lock,
             * but all fault_handlers only check for fatal signals
             * if we return VM_FAULT_RETRY, so we need to drop the
             * mmap_lock here and return 0 if we don't have a fpin.
             */
            if (*fpin == NULL)
                mmap_read_unlock(vmf->vma->vm_mm);
            return 0;
        }
    } else
        __folio_lock(folio);

    return 1;
}

static int filemap_read_folio(struct file *file, struct address_space *mapping,
                              struct folio *folio)
{
    int error;

    panic("%s: END!\n", __func__);
}

/*
 * Asynchronous readahead happens when we find the page and PG_readahead,
 * so we want to possibly extend the readahead further.  We return the file that
 * was pinned if we have to drop the mmap_lock in order to do IO.
 */
static struct file *do_async_mmap_readahead(struct vm_fault *vmf,
                                            struct folio *folio)
{
    struct file *file = vmf->vma->vm_file;
    struct file_ra_state *ra = &file->f_ra;
    DEFINE_READAHEAD(ractl, file, ra, file->f_mapping, vmf->pgoff);
    struct file *fpin = NULL;
    unsigned int mmap_miss;

    /* If we don't want any read-ahead, don't bother */
    if (vmf->vma->vm_flags & VM_RAND_READ || !ra->ra_pages)
        return fpin;

    mmap_miss = READ_ONCE(ra->mmap_miss);
    if (mmap_miss)
        WRITE_ONCE(ra->mmap_miss, --mmap_miss);

    if (folio_test_readahead(folio)) {
        fpin = maybe_unlock_mmap_for_io(vmf, fpin);
        page_cache_async_ra(&ractl, folio, ra->ra_pages);
    }
    return fpin;
}

/**
 * filemap_fault - read in file data for page fault handling
 * @vmf:    struct vm_fault containing details of the fault
 *
 * filemap_fault() is invoked via the vma operations vector for a
 * mapped memory region to read in file data during a page fault.
 *
 * The goto's are kind of ugly, but this streamlines the normal case of having
 * it in the page cache, and handles the special cases reasonably without
 * having a lot of duplicated code.
 *
 * vma->vm_mm->mmap_lock must be held on entry.
 *
 * If our return value has VM_FAULT_RETRY set, it's because the mmap_lock
 * may be dropped before doing I/O or by lock_folio_maybe_drop_mmap().
 *
 * If our return value does not have VM_FAULT_RETRY set, the mmap_lock
 * has not been released.
 *
 * We never return with VM_FAULT_RETRY and a bit from VM_FAULT_ERROR set.
 *
 * Return: bitwise-OR of %VM_FAULT_ codes.
 */
vm_fault_t filemap_fault(struct vm_fault *vmf)
{
    int error;
    struct file *file = vmf->vma->vm_file;
    struct file *fpin = NULL;
    struct address_space *mapping = file->f_mapping;
    struct inode *inode = mapping->host;
    pgoff_t max_idx, index = vmf->pgoff;
    struct folio *folio;
    vm_fault_t ret = 0;
    bool mapping_locked = false;

    max_idx = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
    if (unlikely(index >= max_idx))
        return VM_FAULT_SIGBUS;

    /*
     * Do we have something in the page cache already?
     */
    folio = filemap_get_folio(mapping, index);
    if (likely(folio)) {
        /*
         * We found the page, so try async readahead before waiting for
         * the lock.
         */
        if (!(vmf->flags & FAULT_FLAG_TRIED))
            fpin = do_async_mmap_readahead(vmf, folio);
        if (unlikely(!folio_test_uptodate(folio))) {
            filemap_invalidate_lock_shared(mapping);
            mapping_locked = true;
        }
    } else {
        /* No page in the page cache at all */
        count_vm_event(PGMAJFAULT);
        ret = VM_FAULT_MAJOR;
        fpin = do_sync_mmap_readahead(vmf);
        printk("%s: 0\n", __func__);

     retry_find:
        /*
         * See comment in filemap_create_folio() why we need
         * invalidate_lock
         */
        if (!mapping_locked) {
            filemap_invalidate_lock_shared(mapping);
            mapping_locked = true;
        }
        folio = __filemap_get_folio(mapping, index, FGP_CREAT|FGP_FOR_MMAP,
                                    vmf->gfp_mask);
        if (!folio) {
            if (fpin)
                goto out_retry;
            filemap_invalidate_unlock_shared(mapping);
            return VM_FAULT_OOM;
        }
    }

    if (!lock_folio_maybe_drop_mmap(vmf, folio, &fpin))
        goto out_retry;

    /* Did it get truncated? */
    if (unlikely(folio->mapping != mapping)) {
        folio_unlock(folio);
        folio_put(folio);
        goto retry_find;
    }
    VM_BUG_ON_FOLIO(!folio_contains(folio, index), folio);

    /*
     * We have a locked page in the page cache, now we need to check
     * that it's up-to-date. If not, it is going to be due to an error.
     */
    if (unlikely(!folio_test_uptodate(folio))) {
        /*
         * The page was in cache and uptodate and now it is not.
         * Strange but possible since we didn't hold the page lock all
         * the time. Let's drop everything get the invalidate lock and
         * try again.
         */
        if (!mapping_locked) {
            folio_unlock(folio);
            folio_put(folio);
            goto retry_find;
        }
        goto page_not_uptodate;
    }

    /*
     * We've made it this far and we had to drop our mmap_lock, now is the
     * time to return to the upper layer and have it re-find the vma and
     * redo the fault.
     */
    if (fpin) {
        folio_unlock(folio);
        goto out_retry;
    }
    if (mapping_locked)
        filemap_invalidate_unlock_shared(mapping);

    /*
     * Found the page and have a reference on it.
     * We must recheck i_size under page lock.
     */
    max_idx = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
    if (unlikely(index >= max_idx)) {
        folio_unlock(folio);
        folio_put(folio);
        return VM_FAULT_SIGBUS;
    }

    vmf->page = folio_file_page(folio, index);
    printk("%s: END!\n", __func__);
    return ret | VM_FAULT_LOCKED;

 page_not_uptodate:
    /*
     * Umm, take care of errors if the page isn't up-to-date.
     * Try to re-read it _once_. We do this synchronously,
     * because there really aren't any performance issues here
     * and we need to check for errors.
     */
    fpin = maybe_unlock_mmap_for_io(vmf, fpin);
    error = filemap_read_folio(file, mapping, folio);
    if (fpin)
        goto out_retry;
    folio_put(folio);

    if (!error || error == AOP_TRUNCATED_PAGE)
        goto retry_find;
    filemap_invalidate_unlock_shared(mapping);

    return VM_FAULT_SIGBUS;

 out_retry:
    /*
     * We dropped the mmap_lock, we need to return to the fault handler to
     * re-find the vma and come back and find our hopefully still populated
     * page.
     */
    if (folio)
        folio_put(folio);
    if (mapping_locked)
        filemap_invalidate_unlock_shared(mapping);
    if (fpin)
        fput(fpin);
    return ret | VM_FAULT_RETRY;
}
EXPORT_SYMBOL(filemap_fault);

vm_fault_t filemap_page_mkwrite(struct vm_fault *vmf)
{
    panic("%s: END!\n", __func__);
}

const struct vm_operations_struct generic_file_vm_ops = {
    .fault          = filemap_fault,
    .map_pages      = filemap_map_pages,
    .page_mkwrite   = filemap_page_mkwrite,
};

/* This is used for a general mmap of a disk file */

int generic_file_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct address_space *mapping = file->f_mapping;

    if (!mapping->a_ops->readpage)
        return -ENOEXEC;
    file_accessed(file);
    vma->vm_ops = &generic_file_vm_ops;
    return 0;
}
EXPORT_SYMBOL(generic_file_mmap);

/* Returns true if writeback might be needed or already in progress. */
static bool mapping_needs_writeback(struct address_space *mapping)
{
    return mapping->nrpages;
}

int filemap_check_errors(struct address_space *mapping)
{
    int ret = 0;
    /* Check for outstanding write errors */
    if (test_bit(AS_ENOSPC, &mapping->flags) &&
        test_and_clear_bit(AS_ENOSPC, &mapping->flags))
        ret = -ENOSPC;
    if (test_bit(AS_EIO, &mapping->flags) &&
        test_and_clear_bit(AS_EIO, &mapping->flags))
        ret = -EIO;
    return ret;
}
EXPORT_SYMBOL(filemap_check_errors);

/**
 * filemap_fdatawrite_wbc - start writeback on mapping dirty pages in range
 * @mapping:    address space structure to write
 * @wbc:    the writeback_control controlling the writeout
 *
 * Call writepages on the mapping using the provided wbc to control the
 * writeout.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int filemap_fdatawrite_wbc(struct address_space *mapping,
               struct writeback_control *wbc)
{
    int ret;

    if (!mapping_can_writeback(mapping) ||
        !mapping_tagged(mapping, PAGECACHE_TAG_DIRTY))
        return 0;

#if 0
    wbc_attach_fdatawrite_inode(wbc, mapping->host);
    ret = do_writepages(mapping, wbc);
    wbc_detach_inode(wbc);
    return ret;
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(filemap_fdatawrite_wbc);

/**
 * __filemap_fdatawrite_range - start writeback on mapping dirty pages in range
 * @mapping:    address space structure to write
 * @start:  offset in bytes where the range starts
 * @end:    offset in bytes where the range ends (inclusive)
 * @sync_mode:  enable synchronous operation
 *
 * Start writeback against all of a mapping's dirty pages that lie
 * within the byte offsets <start, end> inclusive.
 *
 * If sync_mode is WB_SYNC_ALL then this is a "data integrity" operation, as
 * opposed to a regular memory cleansing writeback.  The difference between
 * these two operations is that if a dirty page/buffer is encountered, it must
 * be waited upon, and not just skipped over.
 *
 * Return: %0 on success, negative error code otherwise.
 */
int __filemap_fdatawrite_range(struct address_space *mapping, loff_t start,
                               loff_t end, int sync_mode)
{
    struct writeback_control wbc = {
        .sync_mode = sync_mode,
        .nr_to_write = LONG_MAX,
        .range_start = start,
        .range_end = end,
    };

    return filemap_fdatawrite_wbc(mapping, &wbc);
}

static void __filemap_fdatawait_range(struct address_space *mapping,
                                      loff_t start_byte, loff_t end_byte)
{
    pgoff_t index = start_byte >> PAGE_SHIFT;
    pgoff_t end = end_byte >> PAGE_SHIFT;
    struct pagevec pvec;
    int nr_pages;

    if (end_byte < start_byte)
        return;

    pagevec_init(&pvec);
    while (index <= end) {
        unsigned i;

        nr_pages = pagevec_lookup_range_tag(&pvec, mapping, &index, end,
                                            PAGECACHE_TAG_WRITEBACK);
        if (!nr_pages)
            break;

        panic("%s: 1!\n", __func__);
    }
}

/**
 * filemap_fdatawait_range - wait for writeback to complete
 * @mapping:        address space structure to wait for
 * @start_byte:     offset in bytes where the range starts
 * @end_byte:       offset in bytes where the range ends (inclusive)
 *
 * Walk the list of under-writeback pages of the given address space
 * in the given range and wait for all of them.  Check error status of
 * the address space and return it.
 *
 * Since the error status of the address space is cleared by this function,
 * callers are responsible for checking the return value and handling and/or
 * reporting the error.
 *
 * Return: error status of the address space.
 */
int filemap_fdatawait_range(struct address_space *mapping, loff_t start_byte,
                loff_t end_byte)
{
    __filemap_fdatawait_range(mapping, start_byte, end_byte);
    return filemap_check_errors(mapping);
}
EXPORT_SYMBOL(filemap_fdatawait_range);

int filemap_write_and_wait_range(struct address_space *mapping,
                                 loff_t lstart, loff_t lend)
{
    int err = 0;

    if (mapping_needs_writeback(mapping)) {
        err = __filemap_fdatawrite_range(mapping, lstart, lend, WB_SYNC_ALL);
        /*
         * Even if the above returned error, the pages may be
         * written partially (e.g. -ENOSPC), so we wait for it.
         * But the -EIO is special case, it may indicate the worst
         * thing (e.g. bug) happened, so we avoid waiting for it.
         */
        if (err != -EIO) {
            int err2 = filemap_fdatawait_range(mapping, lstart, lend);
            if (!err)
                err = err2;
        } else {
            /* Clear any previously stored errors */
            filemap_check_errors(mapping);
        }
    } else {
        err = filemap_check_errors(mapping);
    }
    return err;
}
EXPORT_SYMBOL(filemap_write_and_wait_range);

noinline int
__filemap_add_folio(struct address_space *mapping,
                    struct folio *folio, pgoff_t index, gfp_t gfp,
                    void **shadowp)
{
    XA_STATE(xas, &mapping->i_pages, index);
    int huge = folio_test_hugetlb(folio);
    long nr = 1;

#if 0
    pr_info("%s: PagePrivate(%d) (%lx)\n",
            __func__, page_has_buffers(&folio->page),
            page_buffers(&folio->page));
#endif
    VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
    VM_BUG_ON_FOLIO(folio_test_swapbacked(folio), folio);
    mapping_set_update(&xas, mapping);

    if (!huge) {
        VM_BUG_ON_FOLIO(index & (folio_nr_pages(folio) - 1), folio);
        xas_set_order(&xas, index, folio_order(folio));
        nr = folio_nr_pages(folio);
    }

    gfp &= GFP_RECLAIM_MASK;
    folio_ref_add(folio, nr);
    folio->mapping = mapping;
    folio->index = xas.xa_index;

    do {
        void *entry, *old = NULL;

        xas_lock_irq(&xas);
        xas_for_each_conflict(&xas, entry) {
            old = entry;
            if (!xa_is_value(entry)) {
                xas_set_err(&xas, -EEXIST);
                goto unlock;
            }
        }

        if (old) {
            panic("%s: old!\n", __func__);
        }

        xas_store(&xas, folio);
        if (xas_error(&xas))
            goto unlock;

        mapping->nrpages += nr;

        /* hugetlb pages do not participate in page cache accounting */
        if (!huge) {
            __lruvec_stat_mod_folio(folio, NR_FILE_PAGES, nr);
        }
     unlock:
        xas_unlock_irq(&xas);
    } while (xas_nomem(&xas, gfp));

    if (xas_error(&xas))
        goto error;

    return 0;

 error:
    folio->mapping = NULL;
    /* Leave page->index set: truncation relies upon it */
    folio_put_refs(folio, nr);
    return xas_error(&xas);
}

int filemap_add_folio(struct address_space *mapping, struct folio *folio,
                      pgoff_t index, gfp_t gfp)
{
    void *shadow = NULL;
    int ret;

    __folio_set_locked(folio);
    ret = __filemap_add_folio(mapping, folio, index, gfp, &shadow);
    if (unlikely(ret)) {
        __folio_clear_locked(folio);
    } else {
        /*
         * The folio might have been evicted from cache only
         * recently, in which case it should be activated like
         * any other repeatedly accessed folio.
         * The exception is folios getting rewritten; evicting other
         * data from the working set, only to cache data that will
         * get overwritten with something else, is a waste of memory.
         */
        WARN_ON_ONCE(folio_test_active(folio));
        if (!(gfp & __GFP_WRITE) && shadow)
            workingset_refault(folio, shadow);
        folio_add_lru(folio);
    }
    return ret;
}
EXPORT_SYMBOL_GPL(filemap_add_folio);

static struct folio *
do_read_cache_folio(struct address_space *mapping,
                    pgoff_t index, filler_t filler, void *data, gfp_t gfp)
{
    struct folio *folio;
    int err;

 repeat:
    folio = filemap_get_folio(mapping, index);
    if (!folio) {
        folio = filemap_alloc_folio(gfp, 0);
        if (!folio)
            return ERR_PTR(-ENOMEM);
        err = filemap_add_folio(mapping, folio, index, gfp);
        if (unlikely(err)) {
            folio_put(folio);
            if (err == -EEXIST)
                goto repeat;
            /* Presumably ENOMEM for xarray node */
            return ERR_PTR(err);
        }

     filler:
        if (filler)
            err = filler(data, &folio->page);
        else
            err = mapping->a_ops->readpage(data, &folio->page);

        if (err < 0) {
            folio_put(folio);
            return ERR_PTR(err);
        }

        folio_wait_locked(folio);
        if (!folio_test_uptodate(folio)) {
            folio_put(folio);
            return ERR_PTR(-EIO);
        }

        goto out;
    }
    if (folio_test_uptodate(folio))
        goto out;

    panic("%s: END!\n", __func__);

 out:
    folio_mark_accessed(folio);
    return folio;
}

static struct page *
do_read_cache_page(struct address_space *mapping,
                   pgoff_t index, filler_t *filler, void *data, gfp_t gfp)
{
    struct folio *folio;

    folio = do_read_cache_folio(mapping, index, filler, data, gfp);
    if (IS_ERR(folio))
        return &folio->page;
    return folio_file_page(folio, index);
}

struct page *read_cache_page(struct address_space *mapping,
                             pgoff_t index, filler_t *filler, void *data)
{
    return do_read_cache_page(mapping, index, filler, data,
                              mapping_gfp_mask(mapping));
}
EXPORT_SYMBOL(read_cache_page);

/*
 * mapping_get_entry - Get a page cache entry.
 * @mapping: the address_space to search
 * @index: The page cache index.
 *
 * Looks up the page cache entry at @mapping & @index.  If it is a folio,
 * it is returned with an increased refcount.  If it is a shadow entry
 * of a previously evicted folio, or a swap entry from shmem/tmpfs,
 * it is returned without further action.
 *
 * Return: The folio, swap or shadow entry, %NULL if nothing is found.
 */
static void *mapping_get_entry(struct address_space *mapping, pgoff_t index)
{
    XA_STATE(xas, &mapping->i_pages, index);
    struct folio *folio;

    rcu_read_lock();
repeat:
    xas_reset(&xas);
    folio = xas_load(&xas);
    if (xas_retry(&xas, folio))
        goto repeat;
    /*
     * A shadow entry of a recently evicted page, or a swap entry from
     * shmem/tmpfs.  Return it without attempting to raise page count.
     */
    if (!folio || xa_is_value(folio))
        goto out;

    if (!folio_try_get_rcu(folio))
        goto repeat;

    if (unlikely(folio != xas_reload(&xas))) {
        folio_put(folio);
        goto repeat;
    }

 out:
    rcu_read_unlock();

    return folio;
}

/**
 * __filemap_get_folio - Find and get a reference to a folio.
 * @mapping: The address_space to search.
 * @index: The page index.
 * @fgp_flags: %FGP flags modify how the folio is returned.
 * @gfp: Memory allocation flags to use if %FGP_CREAT is specified.
 *
 * Looks up the page cache entry at @mapping & @index.
 *
 * @fgp_flags can be zero or more of these flags:
 *
 * * %FGP_ACCESSED - The folio will be marked accessed.
 * * %FGP_LOCK - The folio is returned locked.
 * * %FGP_ENTRY - If there is a shadow / swap / DAX entry, return it
 *   instead of allocating a new folio to replace it.
 * * %FGP_CREAT - If no page is present then a new page is allocated using
 *   @gfp and added to the page cache and the VM's LRU list.
 *   The page is returned locked and with an increased refcount.
 * * %FGP_FOR_MMAP - The caller wants to do its own locking dance if the
 *   page is already in cache.  If the page was allocated, unlock it before
 *   returning so the caller can do the same dance.
 * * %FGP_WRITE - The page will be written to by the caller.
 * * %FGP_NOFS - __GFP_FS will get cleared in gfp.
 * * %FGP_NOWAIT - Don't get blocked by page lock.
 * * %FGP_STABLE - Wait for the folio to be stable (finished writeback)
 *
 * If %FGP_LOCK or %FGP_CREAT are specified then the function may sleep even
 * if the %GFP flags specified for %FGP_CREAT are atomic.
 *
 * If there is a page cache page, it is returned with an increased refcount.
 *
 * Return: The found folio or %NULL otherwise.
 */
struct folio *
__filemap_get_folio(struct address_space *mapping, pgoff_t index,
                    int fgp_flags, gfp_t gfp)
{
    struct folio *folio;

 repeat:
    folio = mapping_get_entry(mapping, index);
    if (xa_is_value(folio)) {
        if (fgp_flags & FGP_ENTRY)
            return folio;
        folio = NULL;
    }
    if (!folio)
        goto no_page;

    if (fgp_flags & FGP_LOCK) {
        if (fgp_flags & FGP_NOWAIT) {
            if (!folio_trylock(folio)) {
                folio_put(folio);
                return NULL;
            }
        } else {
            folio_lock(folio);
        }

        /* Has the page been truncated? */
        if (unlikely(folio->mapping != mapping)) {
            folio_unlock(folio);
            folio_put(folio);
            goto repeat;
        }
        VM_BUG_ON_FOLIO(!folio_contains(folio, index), folio);
    }

    if (fgp_flags & FGP_ACCESSED)
        folio_mark_accessed(folio);
    else if (fgp_flags & FGP_WRITE) {
        /* Clear idle flag for buffer write */
        if (folio_test_idle(folio))
            folio_clear_idle(folio);
    }

    if (fgp_flags & FGP_STABLE)
        folio_wait_stable(folio);

 no_page:
    if (!folio && (fgp_flags & FGP_CREAT)) {
        int err;
        if ((fgp_flags & FGP_WRITE) && mapping_can_writeback(mapping))
            gfp |= __GFP_WRITE;
        if (fgp_flags & FGP_NOFS)
            gfp &= ~__GFP_FS;

        folio = filemap_alloc_folio(gfp, 0);
        if (!folio)
            return NULL;

        if (WARN_ON_ONCE(!(fgp_flags & (FGP_LOCK | FGP_FOR_MMAP))))
            fgp_flags |= FGP_LOCK;

        /* Init accessed so avoid atomic mark_page_accessed later */
        if (fgp_flags & FGP_ACCESSED)
            __folio_set_referenced(folio);

        err = filemap_add_folio(mapping, folio, index, gfp);
        if (unlikely(err)) {
            folio_put(folio);
            folio = NULL;
            if (err == -EEXIST)
                goto repeat;
        }

        /*
         * filemap_add_folio locks the page, and for mmap
         * we expect an unlocked page.
         */
        if (folio && (fgp_flags & FGP_FOR_MMAP))
            folio_unlock(folio);
    }

    return folio;
}
EXPORT_SYMBOL(__filemap_get_folio);

/*
 * PG_waiters is the high bit in the same byte as PG_lock.
 *
 * On x86 (and on many other architectures), we can clear PG_lock and
 * test the sign bit at the same time. But if the architecture does
 * not support that special operation, we just do this all by hand
 * instead.
 *
 * The read of PG_waiters has to be after (or concurrently with) PG_locked
 * being cleared, but a memory barrier should be unnecessary since it is
 * in the same byte as PG_locked.
 */
static inline bool
clear_bit_unlock_is_negative_byte(long nr, volatile void *mem)
{
    clear_bit_unlock(nr, mem);
    /* smp_mb__after_atomic(); */
    return test_bit(PG_waiters, mem);
}

static void folio_wake_bit(struct folio *folio, int bit_nr)
{
    wait_queue_head_t *q = folio_waitqueue(folio);
    struct wait_page_key key;
    unsigned long flags;
    wait_queue_entry_t bookmark;

    key.folio = folio;
    key.bit_nr = bit_nr;
    key.page_match = 0;

    bookmark.flags = 0;
    bookmark.private = NULL;
    bookmark.func = NULL;
    INIT_LIST_HEAD(&bookmark.entry);

    spin_lock_irqsave(&q->lock, flags);
    __wake_up_locked_key_bookmark(q, TASK_NORMAL, &key, &bookmark);

    while (bookmark.flags & WQ_FLAG_BOOKMARK) {
        /*
         * Take a breather from holding the lock,
         * allow pages that finish wake up asynchronously
         * to acquire the lock and remove themselves
         * from wait queue
         */
        spin_unlock_irqrestore(&q->lock, flags);
        cpu_relax();
        spin_lock_irqsave(&q->lock, flags);
        __wake_up_locked_key_bookmark(q, TASK_NORMAL, &key, &bookmark);
    }

    /*
     * It's possible to miss clearing waiters here, when we woke our page
     * waiters, but the hashed waitqueue has waiters for other pages on it.
     * That's okay, it's a rare case. The next waker will clear it.
     *
     * Note that, depending on the page pool (buddy, hugetlb, ZONE_DEVICE,
     * other), the flag may be cleared in the course of freeing the page;
     * but that is not required for correctness.
     */
    if (!waitqueue_active(q) || !key.page_match)
        folio_clear_waiters(folio);

    spin_unlock_irqrestore(&q->lock, flags);
}

/**
 * folio_unlock - Unlock a locked folio.
 * @folio: The folio.
 *
 * Unlocks the folio and wakes up any thread sleeping on the page lock.
 *
 * Context: May be called from interrupt or process context.  May not be
 * called from NMI context.
 */
void folio_unlock(struct folio *folio)
{
    /* Bit 7 allows x86 to check the byte's sign bit */
    BUILD_BUG_ON(PG_waiters != 7);
    BUILD_BUG_ON(PG_locked > 7);
    VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
    if (clear_bit_unlock_is_negative_byte(PG_locked, folio_flags(folio, 0)))
        folio_wake_bit(folio, PG_locked);
}
EXPORT_SYMBOL(folio_unlock);

void __init pagecache_init(void)
{
    int i;

    for (i = 0; i < PAGE_WAIT_TABLE_SIZE; i++)
        init_waitqueue_head(&folio_wait_table[i]);

#if 0
    page_writeback_init();
#endif
}

/*
 * The page wait code treats the "wait->flags" somewhat unusually, because
 * we have multiple different kinds of waits, not just the usual "exclusive"
 * one.
 *
 * We have:
 *
 *  (a) no special bits set:
 *
 *  We're just waiting for the bit to be released, and when a waker
 *  calls the wakeup function, we set WQ_FLAG_WOKEN and wake it up,
 *  and remove it from the wait queue.
 *
 *  Simple and straightforward.
 *
 *  (b) WQ_FLAG_EXCLUSIVE:
 *
 *  The waiter is waiting to get the lock, and only one waiter should
 *  be woken up to avoid any thundering herd behavior. We'll set the
 *  WQ_FLAG_WOKEN bit, wake it up, and remove it from the wait queue.
 *
 *  This is the traditional exclusive wait.
 *
 *  (c) WQ_FLAG_EXCLUSIVE | WQ_FLAG_CUSTOM:
 *
 *  The waiter is waiting to get the bit, and additionally wants the
 *  lock to be transferred to it for fair lock behavior. If the lock
 *  cannot be taken, we stop walking the wait queue without waking
 *  the waiter.
 *
 *  This is the "fair lock handoff" case, and in addition to setting
 *  WQ_FLAG_WOKEN, we set WQ_FLAG_DONE to let the waiter easily see
 *  that it now has the lock.
 */
static int wake_page_function(wait_queue_entry_t *wait,
                              unsigned mode, int sync, void *arg)
{
    unsigned int flags;
    struct wait_page_key *key = arg;
    struct wait_page_queue *wait_page =
        container_of(wait, struct wait_page_queue, wait);

    if (!wake_page_match(wait_page, key))
        return 0;

    /*
     * If it's a lock handoff wait, we get the bit for it, and
     * stop walking (and do not wake it up) if we can't.
     */
    flags = wait->flags;
    if (flags & WQ_FLAG_EXCLUSIVE) {
        if (test_bit(key->bit_nr, &key->folio->flags))
            return -1;
        if (flags & WQ_FLAG_CUSTOM) {
            if (test_and_set_bit(key->bit_nr, &key->folio->flags))
                return -1;
            flags |= WQ_FLAG_DONE;
        }
    }

    /*
     * We are holding the wait-queue lock, but the waiter that
     * is waiting for this will be checking the flags without
     * any locking.
     *
     * So update the flags atomically, and wake up the waiter
     * afterwards to avoid any races. This store-release pairs
     * with the load-acquire in folio_wait_bit_common().
     */
    smp_store_release(&wait->flags, flags | WQ_FLAG_WOKEN);
    wake_up_state(wait->private, mode);

    /*
     * Ok, we have successfully done what we're waiting for,
     * and we can unconditionally remove the wait entry.
     *
     * Note that this pairs with the "finish_wait()" in the
     * waiter, and has to be the absolute last thing we do.
     * After this list_del_init(&wait->entry) the wait entry
     * might be de-allocated and the process might even have
     * exited.
     */
    list_del_init_careful(&wait->entry);
    return (flags & WQ_FLAG_EXCLUSIVE) != 0;
}

/*
 * Attempt to check (or get) the folio flag, and mark us done
 * if successful.
 */
static inline bool folio_trylock_flag(struct folio *folio, int bit_nr,
                                      struct wait_queue_entry *wait)
{
    if (wait->flags & WQ_FLAG_EXCLUSIVE) {
        if (test_and_set_bit(bit_nr, &folio->flags))
            return false;
    } else if (test_bit(bit_nr, &folio->flags))
        return false;

    wait->flags |= WQ_FLAG_WOKEN | WQ_FLAG_DONE;
    return true;
}

/* How many times do we accept lock stealing from under a waiter? */
int sysctl_page_lock_unfairness = 5;

static inline int
folio_wait_bit_common(struct folio *folio, int bit_nr,
                      int state, enum behavior behavior)
{
    wait_queue_head_t *q = folio_waitqueue(folio);
    int unfairness = sysctl_page_lock_unfairness;
    struct wait_page_queue wait_page;
    wait_queue_entry_t *wait = &wait_page.wait;
    bool thrashing = false;
    bool delayacct = false;
    unsigned long pflags;

    if (bit_nr == PG_locked &&
        !folio_test_uptodate(folio) && folio_test_workingset(folio)) {
        if (!folio_test_swapbacked(folio)) {
            delayacct = true;
        }
        thrashing = true;
    }

    init_wait(wait);
    wait->func = wake_page_function;
    wait_page.folio = folio;
    wait_page.bit_nr = bit_nr;

 repeat:
    wait->flags = 0;
    if (behavior == EXCLUSIVE) {
        wait->flags = WQ_FLAG_EXCLUSIVE;
        if (--unfairness < 0)
            wait->flags |= WQ_FLAG_CUSTOM;
    }

    /*
     * Do one last check whether we can get the
     * page bit synchronously.
     *
     * Do the folio_set_waiters() marking before that
     * to let any waker we _just_ missed know they
     * need to wake us up (otherwise they'll never
     * even go to the slow case that looks at the
     * page queue), and add ourselves to the wait
     * queue if we need to sleep.
     *
     * This part needs to be done under the queue
     * lock to avoid races.
     */
    spin_lock_irq(&q->lock);
    folio_set_waiters(folio);
    if (!folio_trylock_flag(folio, bit_nr, wait))
        __add_wait_queue_entry_tail(q, wait);
    spin_unlock_irq(&q->lock);

    /*
     * From now on, all the logic will be based on
     * the WQ_FLAG_WOKEN and WQ_FLAG_DONE flag, to
     * see whether the page bit testing has already
     * been done by the wake function.
     *
     * We can drop our reference to the folio.
     */
    if (behavior == DROP)
        folio_put(folio);

    /*
     * Note that until the "finish_wait()", or until
     * we see the WQ_FLAG_WOKEN flag, we need to
     * be very careful with the 'wait->flags', because
     * we may race with a waker that sets them.
     */
    for (;;) {
        unsigned int flags;

        set_current_state(state);

        /* Loop until we've been woken or interrupted */
        flags = smp_load_acquire(&wait->flags);
        if (!(flags & WQ_FLAG_WOKEN)) {
            if (signal_pending_state(state, current))
                break;

            io_schedule();
            continue;
        }

        /* If we were non-exclusive, we're done */
        if (behavior != EXCLUSIVE)
            break;

        /* If the waker got the lock for us, we're done */
        if (flags & WQ_FLAG_DONE)
            break;

        /*
         * Otherwise, if we're getting the lock, we need to
         * try to get it ourselves.
         *
         * And if that fails, we'll have to retry this all.
         */
        if (unlikely(test_and_set_bit(bit_nr, folio_flags(folio, 0))))
            goto repeat;

        wait->flags |= WQ_FLAG_DONE;
        break;
    }

    /*
     * If a signal happened, this 'finish_wait()' may remove the last
     * waiter from the wait-queues, but the folio waiters bit will remain
     * set. That's ok. The next wakeup will take care of it, and trying
     * to do it here would be difficult and prone to races.
     */
    finish_wait(q, wait);

    if (thrashing) {
#if 0
        if (delayacct)
            delayacct_thrashing_end();
        psi_memstall_leave(&pflags);
#endif
        panic("%s: thrashing!\n", __func__);
    }

    /*
     * NOTE! The wait->flags weren't stable until we've done the
     * 'finish_wait()', and we could have exited the loop above due
     * to a signal, and had a wakeup event happen after the signal
     * test but before the 'finish_wait()'.
     *
     * So only after the finish_wait() can we reliably determine
     * if we got woken up or not, so we can now figure out the final
     * return value based on that state without races.
     *
     * Also note that WQ_FLAG_WOKEN is sufficient for a non-exclusive
     * waiter, but an exclusive one requires WQ_FLAG_DONE.
     */
    if (behavior == EXCLUSIVE)
        return wait->flags & WQ_FLAG_DONE ? 0 : -EINTR;

    return wait->flags & WQ_FLAG_WOKEN ? 0 : -EINTR;
}

void folio_wait_bit(struct folio *folio, int bit_nr)
{
    folio_wait_bit_common(folio, bit_nr, TASK_UNINTERRUPTIBLE, SHARED);
}
EXPORT_SYMBOL(folio_wait_bit);

/**
 * __folio_lock - Get a lock on the folio, assuming we need to sleep to get it.
 * @folio: The folio to lock
 */
void __folio_lock(struct folio *folio)
{
    folio_wait_bit_common(folio, PG_locked, TASK_UNINTERRUPTIBLE, EXCLUSIVE);
}
EXPORT_SYMBOL(__folio_lock);

static inline
struct folio *find_get_entry(struct xa_state *xas, pgoff_t max, xa_mark_t mark)
{
    struct folio *folio;

 retry:
    if (mark == XA_PRESENT)
        folio = xas_find(xas, max);
    else
        folio = xas_find_marked(xas, max, mark);

    if (xas_retry(xas, folio))
        goto retry;
    /*
     * A shadow entry of a recently evicted page, a swap
     * entry from shmem/tmpfs or a DAX entry.  Return it
     * without attempting to raise page count.
     */
    if (!folio || xa_is_value(folio))
        return folio;

    if (!folio_try_get_rcu(folio))
        goto reset;

    if (unlikely(folio != xas_reload(xas))) {
        folio_put(folio);
        goto reset;
    }

    return folio;
 reset:
    xas_reset(xas);
    goto retry;
}

/**
 * find_get_pages_range_tag - Find and return head pages matching @tag.
 * @mapping:    the address_space to search
 * @index:  the starting page index
 * @end:    The final page index (inclusive)
 * @tag:    the tag index
 * @nr_pages:   the maximum number of pages
 * @pages:  where the resulting pages are placed
 *
 * Like find_get_pages_range(), except we only return head pages which are
 * tagged with @tag.  @index is updated to the index immediately after the
 * last page we return, ready for the next iteration.
 *
 * Return: the number of pages which were found.
 */
unsigned find_get_pages_range_tag(struct address_space *mapping,
                                  pgoff_t *index, pgoff_t end, xa_mark_t tag,
                                  unsigned int nr_pages, struct page **pages)
{
    XA_STATE(xas, &mapping->i_pages, *index);
    struct folio *folio;
    unsigned ret = 0;

    if (unlikely(!nr_pages))
        return 0;

    rcu_read_lock();
    while ((folio = find_get_entry(&xas, end, tag))) {
        /*
         * Shadow entries should never be tagged, but this iteration
         * is lockless so there is a window for page reclaim to evict
         * a page we saw tagged.  Skip over it.
         */
        if (xa_is_value(folio))
            continue;

        pages[ret] = &folio->page;
        if (++ret == nr_pages) {
            *index = folio->index + folio_nr_pages(folio);
            goto out;
        }
    }

    /*
     * We come here when we got to @end. We take care to not overflow the
     * index @index as it confuses some of the callers. This breaks the
     * iteration when there is a page at index -1 but that is already
     * broken anyway.
     */
    if (end == (pgoff_t)-1)
        *index = (pgoff_t)-1;
    else
        *index = end + 1;

 out:
    rcu_read_unlock();

    return ret;
}
EXPORT_SYMBOL(find_get_pages_range_tag);

/**
 * find_lock_entries - Find a batch of pagecache entries.
 * @mapping:    The address_space to search.
 * @start:  The starting page cache index.
 * @end:    The final page index (inclusive).
 * @fbatch: Where the resulting entries are placed.
 * @indices:    The cache indices of the entries in @fbatch.
 *
 * find_lock_entries() will return a batch of entries from @mapping.
 * Swap, shadow and DAX entries are included.  Folios are returned
 * locked and with an incremented refcount.  Folios which are locked
 * by somebody else or under writeback are skipped.  Folios which are
 * partially outside the range are not returned.
 *
 * The entries have ascending indexes.  The indices may not be consecutive
 * due to not-present entries, large folios, folios which could not be
 * locked or folios under writeback.
 *
 * Return: The number of entries which were found.
 */
unsigned find_lock_entries(struct address_space *mapping,
                           pgoff_t start, pgoff_t end,
                           struct folio_batch *fbatch, pgoff_t *indices)
{
    XA_STATE(xas, &mapping->i_pages, start);
    struct folio *folio;

    rcu_read_lock();
    while ((folio = find_get_entry(&xas, end, XA_PRESENT))) {
        if (!xa_is_value(folio)) {
            if (folio->index < start)
                goto put;
            if (folio->index + folio_nr_pages(folio) - 1 > end)
                goto put;
            if (!folio_trylock(folio))
                goto put;
            if (folio->mapping != mapping ||
                folio_test_writeback(folio))
                goto unlock;
            VM_BUG_ON_FOLIO(!folio_contains(folio, xas.xa_index), folio);
        }
        indices[fbatch->nr] = xas.xa_index;
        if (!folio_batch_add(fbatch, folio))
            break;
        continue;
unlock:
        folio_unlock(folio);
put:
        folio_put(folio);
    }
    rcu_read_unlock();

    return folio_batch_count(fbatch);
}

/**
 * filemap_release_folio() - Release fs-specific metadata on a folio.
 * @folio: The folio which the kernel is trying to free.
 * @gfp: Memory allocation flags (and I/O mode).
 *
 * The address_space is trying to release any data attached to a folio
 * (presumably at folio->private).
 *
 * This will also be called if the private_2 flag is set on a page,
 * indicating that the folio has other metadata associated with it.
 *
 * The @gfp argument specifies whether I/O may be performed to release
 * this page (__GFP_IO), and whether the call may block
 * (__GFP_RECLAIM & __GFP_FS).
 *
 * Return: %true if the release was successful, otherwise %false.
 */
bool filemap_release_folio(struct folio *folio, gfp_t gfp)
{
    struct address_space * const mapping = folio->mapping;

    BUG_ON(!folio_test_locked(folio));
    if (folio_test_writeback(folio))
        return false;

    if (mapping && mapping->a_ops->releasepage)
        return mapping->a_ops->releasepage(&folio->page, gfp);
    return try_to_free_buffers(&folio->page);
}
EXPORT_SYMBOL(filemap_release_folio);

static void filemap_unaccount_folio(struct address_space *mapping,
                                    struct folio *folio)
{
    long nr;

    VM_BUG_ON_FOLIO(folio_mapped(folio), folio);
    if (unlikely(folio_mapped(folio))) {
        panic("%s: folio_mapped!\n", __func__);
    }

    /* hugetlb folios do not participate in page cache accounting. */
    if (folio_test_hugetlb(folio))
        return;

    nr = folio_nr_pages(folio);

    __lruvec_stat_mod_folio(folio, NR_FILE_PAGES, -nr);
    if (folio_test_swapbacked(folio)) {
        __lruvec_stat_mod_folio(folio, NR_SHMEM, -nr);
    }

    /*
     * At this point folio must be either written or cleaned by
     * truncate.  Dirty folio here signals a bug and loss of
     * unwritten data - on ordinary filesystems.
     *
     * But it's harmless on in-memory filesystems like tmpfs; and can
     * occur when a driver which did get_user_pages() sets page dirty
     * before putting it, while the inode is being finally evicted.
     *
     * Below fixes dirty accounting after removing the folio entirely
     * but leaves the dirty flag set: it has no effect for truncated
     * folio and anyway will be cleared before returning folio to
     * buddy allocator.
     */
    if (WARN_ON_ONCE(folio_test_dirty(folio) && mapping_can_writeback(mapping)))
        folio_account_cleaned(folio, inode_to_wb(mapping->host));
}

/*
 * page_cache_delete_batch - delete several folios from page cache
 * @mapping: the mapping to which folios belong
 * @fbatch: batch of folios to delete
 *
 * The function walks over mapping->i_pages and removes folios passed in
 * @fbatch from the mapping. The function expects @fbatch to be sorted
 * by page index and is optimised for it to be dense.
 * It tolerates holes in @fbatch (mapping entries at those indices are not
 * modified).
 *
 * The function expects the i_pages lock to be held.
 */
static void page_cache_delete_batch(struct address_space *mapping,
                                    struct folio_batch *fbatch)
{
    XA_STATE(xas, &mapping->i_pages, fbatch->folios[0]->index);
    long total_pages = 0;
    int i = 0;
    struct folio *folio;

    mapping_set_update(&xas, mapping);
    xas_for_each(&xas, folio, ULONG_MAX) {
        if (i >= folio_batch_count(fbatch))
            break;

        /* A swap/dax/shadow entry got inserted? Skip it. */
        if (xa_is_value(folio))
            continue;
        /*
         * A page got inserted in our range? Skip it. We have our
         * pages locked so they are protected from being removed.
         * If we see a page whose index is higher than ours, it
         * means our page has been removed, which shouldn't be
         * possible because we're holding the PageLock.
         */
        if (folio != fbatch->folios[i]) {
            VM_BUG_ON_FOLIO(folio->index > fbatch->folios[i]->index, folio);
            continue;
        }

        WARN_ON_ONCE(!folio_test_locked(folio));

        folio->mapping = NULL;
        /* Leave folio->index set: truncation lookup relies on it */

        i++;
        xas_store(&xas, NULL);
        total_pages += folio_nr_pages(folio);
    }
    mapping->nrpages -= total_pages;
}

void filemap_free_folio(struct address_space *mapping, struct folio *folio)
{
    void (*freepage)(struct page *);
    int refs = 1;

    freepage = mapping->a_ops->freepage;
    if (freepage)
        freepage(&folio->page);

    if (folio_test_large(folio) && !folio_test_hugetlb(folio))
        refs = folio_nr_pages(folio);
    folio_put_refs(folio, refs);
}

void delete_from_page_cache_batch(struct address_space *mapping,
                                  struct folio_batch *fbatch)
{
    int i;

    if (!folio_batch_count(fbatch))
        return;

    spin_lock(&mapping->host->i_lock);
    xa_lock_irq(&mapping->i_pages);
    for (i = 0; i < folio_batch_count(fbatch); i++) {
        struct folio *folio = fbatch->folios[i];

        filemap_unaccount_folio(mapping, folio);
    }
    page_cache_delete_batch(mapping, fbatch);
    xa_unlock_irq(&mapping->i_pages);
    if (mapping_shrinkable(mapping))
        inode_add_lru(mapping->host);
    spin_unlock(&mapping->host->i_lock);

    for (i = 0; i < folio_batch_count(fbatch); i++)
        filemap_free_folio(mapping, fbatch->folios[i]);
}

/**
 * find_get_entries - gang pagecache lookup
 * @mapping:    The address_space to search
 * @start:  The starting page cache index
 * @end:    The final page index (inclusive).
 * @fbatch: Where the resulting entries are placed.
 * @indices:    The cache indices corresponding to the entries in @entries
 *
 * find_get_entries() will search for and return a batch of entries in
 * the mapping.  The entries are placed in @fbatch.  find_get_entries()
 * takes a reference on any actual folios it returns.
 *
 * The entries have ascending indexes.  The indices may not be consecutive
 * due to not-present entries or large folios.
 *
 * Any shadow entries of evicted folios, or swap entries from
 * shmem/tmpfs, are included in the returned array.
 *
 * Return: The number of entries which were found.
 */
unsigned find_get_entries(struct address_space *mapping,
                          pgoff_t start, pgoff_t end,
                          struct folio_batch *fbatch, pgoff_t *indices)
{
    XA_STATE(xas, &mapping->i_pages, start);
    struct folio *folio;

    rcu_read_lock();
    while ((folio = find_get_entry(&xas, end, XA_PRESENT)) != NULL) {
        indices[fbatch->nr] = xas.xa_index;
        if (!folio_batch_add(fbatch, folio))
            break;
    }
    rcu_read_unlock();

    return folio_batch_count(fbatch);
}

/*
 * After completing I/O on a page, call this routine to update the page
 * flags appropriately
 */
void page_endio(struct page *page, bool is_write, int err)
{
    if (!is_write) {
        if (!err) {
            SetPageUptodate(page);
        } else {
            ClearPageUptodate(page);
            SetPageError(page);
        }
        unlock_page(page);
    } else {
        if (err) {
            struct address_space *mapping;

            SetPageError(page);
            printk("%s: before page_mapping ...\n", __func__);
            mapping = page_mapping(page);
            if (mapping)
                mapping_set_error(mapping, err);
        }
        end_page_writeback(page);
    }
}
EXPORT_SYMBOL_GPL(page_endio);

/**
 * folio_end_writeback - End writeback against a folio.
 * @folio: The folio.
 */
void folio_end_writeback(struct folio *folio)
{
    panic("%s: END!\n", __func__);
}

/*
 * filemap_get_read_batch - Get a batch of folios for read
 *
 * Get a batch of folios which represent a contiguous range of bytes in
 * the file.  No exceptional entries will be returned.  If @index is in
 * the middle of a folio, the entire folio will be returned.  The last
 * folio in the batch may have the readahead flag set or the uptodate flag
 * clear so that the caller can take the appropriate action.
 */
static void filemap_get_read_batch(struct address_space *mapping,
                                   pgoff_t index, pgoff_t max,
                                   struct folio_batch *fbatch)
{
    XA_STATE(xas, &mapping->i_pages, index);
    struct folio *folio;

    rcu_read_lock();
    for (folio = xas_load(&xas); folio; folio = xas_next(&xas)) {
        if (xas_retry(&xas, folio))
            continue;
        if (xas.xa_index > max || xa_is_value(folio))
            break;
        if (!folio_try_get_rcu(folio))
            goto retry;

        if (unlikely(folio != xas_reload(&xas)))
            goto put_folio;

        if (!folio_batch_add(fbatch, folio))
            break;
        if (!folio_test_uptodate(folio))
            break;
        if (folio_test_readahead(folio))
            break;
        xas_advance(&xas, folio->index + folio_nr_pages(folio) - 1);
        continue;
put_folio:
        folio_put(folio);
retry:
        xas_reset(&xas);
    }
    rcu_read_unlock();
}

static int filemap_create_folio(struct file *file,
                                struct address_space *mapping, pgoff_t index,
                                struct folio_batch *fbatch)
{
    panic("%s: END!\n", __func__);
}

static int
filemap_readahead(struct kiocb *iocb, struct file *file,
                  struct address_space *mapping, struct folio *folio,
                  pgoff_t last_index)
{
    DEFINE_READAHEAD(ractl, file, &file->f_ra, mapping, folio->index);

    if (iocb->ki_flags & IOCB_NOIO)
        return -EAGAIN;
    page_cache_async_ra(&ractl, folio, last_index - folio->index);
    return 0;
}

/**
 * folio_put_wait_locked - Drop a reference and wait for it to be unlocked
 * @folio: The folio to wait for.
 * @state: The sleep state (TASK_KILLABLE, TASK_UNINTERRUPTIBLE, etc).
 *
 * The caller should hold a reference on @folio.  They expect the page to
 * become unlocked relatively soon, but do not wish to hold up migration
 * (for example) by holding the reference while waiting for the folio to
 * come unlocked.  After this function returns, the caller should not
 * dereference @folio.
 *
 * Return: 0 if the folio was unlocked or -EINTR if interrupted by a signal.
 */
int folio_put_wait_locked(struct folio *folio, int state)
{
    return folio_wait_bit_common(folio, PG_locked, state, DROP);
}

static int __folio_lock_async(struct folio *folio, struct wait_page_queue *wait)
{
    panic("%s: END!\n", __func__);
}

static int filemap_update_page(struct kiocb *iocb,
                               struct address_space *mapping,
                               struct iov_iter *iter,
                               struct folio *folio)
{
    int error;

    if (iocb->ki_flags & IOCB_NOWAIT) {
        if (!filemap_invalidate_trylock_shared(mapping))
            return -EAGAIN;
    } else {
        filemap_invalidate_lock_shared(mapping);
    }

    if (!folio_trylock(folio)) {
        error = -EAGAIN;
        if (iocb->ki_flags & (IOCB_NOWAIT | IOCB_NOIO))
            goto unlock_mapping;
        if (!(iocb->ki_flags & IOCB_WAITQ)) {
            filemap_invalidate_unlock_shared(mapping);
            /*
             * This is where we usually end up waiting for a
             * previously submitted readahead to finish.
             */
            folio_put_wait_locked(folio, TASK_KILLABLE);
            return AOP_TRUNCATED_PAGE;
        }
        error = __folio_lock_async(folio, iocb->ki_waitq);
        if (error)
            goto unlock_mapping;
    }

    panic("%s: END!\n", __func__);
 unlock:
    folio_unlock(folio);
 unlock_mapping:
    filemap_invalidate_unlock_shared(mapping);
    if (error == AOP_TRUNCATED_PAGE)
        folio_put(folio);
    return error;
}

static int filemap_get_pages(struct kiocb *iocb, struct iov_iter *iter,
                             struct folio_batch *fbatch)
{
    struct file *filp = iocb->ki_filp;
    struct address_space *mapping = filp->f_mapping;
    struct file_ra_state *ra = &filp->f_ra;
    pgoff_t index = iocb->ki_pos >> PAGE_SHIFT;
    pgoff_t last_index;
    struct folio *folio;
    int err = 0;

    last_index = DIV_ROUND_UP(iocb->ki_pos + iter->count, PAGE_SIZE);
 retry:
#if 0
    if (fatal_signal_pending(current))
        return -EINTR;
#endif
    filemap_get_read_batch(mapping, index, last_index, fbatch);
    if (!folio_batch_count(fbatch)) {
        if (iocb->ki_flags & IOCB_NOIO)
            return -EAGAIN;
        page_cache_sync_readahead(mapping, ra, filp, index,
                                  last_index - index);
        filemap_get_read_batch(mapping, index, last_index, fbatch);
    }
    if (!folio_batch_count(fbatch)) {
        if (iocb->ki_flags & (IOCB_NOWAIT | IOCB_WAITQ))
            return -EAGAIN;
        err = filemap_create_folio(filp, mapping,
                                   iocb->ki_pos >> PAGE_SHIFT, fbatch);
        if (err == AOP_TRUNCATED_PAGE)
            goto retry;
        return err;
    }

    folio = fbatch->folios[folio_batch_count(fbatch) - 1];
    if (folio_test_readahead(folio)) {
        err = filemap_readahead(iocb, filp, mapping, folio, last_index);
        if (err)
            goto err;
    }
    if (!folio_test_uptodate(folio)) {
        if ((iocb->ki_flags & IOCB_WAITQ) && folio_batch_count(fbatch) > 1)
            iocb->ki_flags |= IOCB_NOWAIT;
        err = filemap_update_page(iocb, mapping, iter, folio);
        if (err)
            goto err;
    }

    return 0;
 err:
    if (err < 0)
        folio_put(folio);
    if (likely(--fbatch->nr))
        return 0;
    if (err == AOP_TRUNCATED_PAGE)
        goto retry;
    return err;
}

/**
 * filemap_read - Read data from the page cache.
 * @iocb: The iocb to read.
 * @iter: Destination for the data.
 * @already_read: Number of bytes already read by the caller.
 *
 * Copies data from the page cache.  If the data is not currently present,
 * uses the readahead and readpage address_space operations to fetch it.
 *
 * Return: Total number of bytes copied, including those already read by
 * the caller.  If an error happens before any bytes are copied, returns
 * a negative error number.
 */
ssize_t filemap_read(struct kiocb *iocb, struct iov_iter *iter,
                     ssize_t already_read)
{
    struct file *filp = iocb->ki_filp;
    struct file_ra_state *ra = &filp->f_ra;
    struct address_space *mapping = filp->f_mapping;
    struct inode *inode = mapping->host;
    struct folio_batch fbatch;
    int i, error = 0;
    bool writably_mapped;
    loff_t isize, end_offset;

    if (unlikely(iocb->ki_pos >= inode->i_sb->s_maxbytes))
        return 0;
    if (unlikely(!iov_iter_count(iter)))
        return 0;

    iov_iter_truncate(iter, inode->i_sb->s_maxbytes);
    folio_batch_init(&fbatch);

    do {
        cond_resched();

        /*
         * If we've already successfully copied some data, then we
         * can no longer safely return -EIOCBQUEUED. Hence mark
         * an async read NOWAIT at that point.
         */
        if ((iocb->ki_flags & IOCB_WAITQ) && already_read)
            iocb->ki_flags |= IOCB_NOWAIT;

        if (unlikely(iocb->ki_pos >= i_size_read(inode)))
            break;

        error = filemap_get_pages(iocb, iter, &fbatch);
        if (error < 0)
            break;

        /*
         * i_size must be checked after we know the pages are Uptodate.
         *
         * Checking i_size after the check allows us to calculate
         * the correct value for "nr", which means the zero-filled
         * part of the page is not copied back to userspace (unless
         * another truncate extends the file - this is desired though).
         */
        isize = i_size_read(inode);
        if (unlikely(iocb->ki_pos >= isize))
            goto put_folios;
        end_offset = min_t(loff_t, isize, iocb->ki_pos + iter->count);

        /*
         * Once we start copying data, we don't want to be touching any
         * cachelines that might be contended:
         */
        writably_mapped = mapping_writably_mapped(mapping);

        /*
         * When a sequential read accesses a page several times, only
         * mark it as accessed the first time.
         */
        if (iocb->ki_pos >> PAGE_SHIFT != ra->prev_pos >> PAGE_SHIFT)
            folio_mark_accessed(fbatch.folios[0]);

        for (i = 0; i < folio_batch_count(&fbatch); i++) {
            struct folio *folio = fbatch.folios[i];
            size_t fsize = folio_size(folio);
            size_t offset = iocb->ki_pos & (fsize - 1);
            size_t bytes = min_t(loff_t, end_offset - iocb->ki_pos,
                                 fsize - offset);
            size_t copied;

            if (end_offset < folio_pos(folio))
                break;
            if (i > 0)
                folio_mark_accessed(folio);
            /*
             * If users can be writing to this folio using arbitrary
             * virtual addresses, take care of potential aliasing
             * before reading the folio on the kernel side.
             */
            if (writably_mapped)
                flush_dcache_folio(folio);

            copied = copy_folio_to_iter(folio, offset, bytes, iter);

            already_read += copied;
            iocb->ki_pos += copied;
            ra->prev_pos = iocb->ki_pos;

            if (copied < bytes) {
                error = -EFAULT;
                break;
            }
        }

     put_folios:
        for (i = 0; i < folio_batch_count(&fbatch); i++)
            folio_put(fbatch.folios[i]);
        folio_batch_init(&fbatch);
    } while (iov_iter_count(iter) && iocb->ki_pos < isize && !error);

    file_accessed(filp);

    return already_read ? already_read : error;
}

/**
 * generic_file_read_iter - generic filesystem read routine
 * @iocb:   kernel I/O control block
 * @iter:   destination for the data read
 *
 * This is the "read_iter()" routine for all filesystems
 * that can use the page cache directly.
 *
 * The IOCB_NOWAIT flag in iocb->ki_flags indicates that -EAGAIN shall
 * be returned when no data can be read without waiting for I/O requests
 * to complete; it doesn't prevent readahead.
 *
 * The IOCB_NOIO flag in iocb->ki_flags indicates that no new I/O
 * requests shall be made for the read or for readahead.  When no data
 * can be read, -EAGAIN shall be returned.  When readahead would be
 * triggered, a partial, possibly empty read shall be returned.
 *
 * Return:
 * * number of bytes copied, even for partial reads
 * * negative error code (or 0 if IOCB_NOIO) if nothing was read
 */
ssize_t
generic_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
    size_t count = iov_iter_count(iter);
    ssize_t retval = 0;

    if (!count)
        return 0; /* skip atime */

    if (iocb->ki_flags & IOCB_DIRECT) {
        panic("%s: IOCB_DIRECT!\n", __func__);
    }
    return filemap_read(iocb, iter, retval);
}
EXPORT_SYMBOL(generic_file_read_iter);

/**
 * generic_file_write_iter - write data to a file
 * @iocb:   IO state structure
 * @from:   iov_iter with data to write
 *
 * This is a wrapper around __generic_file_write_iter() to be used by most
 * filesystems. It takes care of syncing the file in case of O_SYNC file
 * and acquires i_rwsem as needed.
 * Return:
 * * negative error code if no data has been written at all of
 *   vfs_fsync_range() failed for a synchronous write
 * * number of bytes written, even for truncated writes
 */
ssize_t generic_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
    panic("%s: END!\n", __func__);
}

/**
 * filemap_remove_folio - Remove folio from page cache.
 * @folio: The folio.
 *
 * This must be called only on folios that are locked and have been
 * verified to be in the page cache.  It will never put the folio into
 * the free list because the caller has a reference on the page.
 */
void filemap_remove_folio(struct folio *folio)
{
#if 0
    struct address_space *mapping = folio->mapping;

    BUG_ON(!folio_test_locked(folio));
    spin_lock(&mapping->host->i_lock);
    xa_lock_irq(&mapping->i_pages);
    __filemap_remove_folio(folio, NULL);
    xa_unlock_irq(&mapping->i_pages);
    if (mapping_shrinkable(mapping))
        inode_add_lru(mapping->host);
    spin_unlock(&mapping->host->i_lock);

    filemap_free_folio(mapping, folio);
#endif
    panic("%s: END!\n", __func__);
}

/**
 * page_cache_next_miss() - Find the next gap in the page cache.
 * @mapping: Mapping.
 * @index: Index.
 * @max_scan: Maximum range to search.
 *
 * Search the range [index, min(index + max_scan - 1, ULONG_MAX)] for the
 * gap with the lowest index.
 *
 * This function may be called under the rcu_read_lock.  However, this will
 * not atomically search a snapshot of the cache at a single point in time.
 * For example, if a gap is created at index 5, then subsequently a gap is
 * created at index 10, page_cache_next_miss covering both indices may
 * return 10 if called under the rcu_read_lock.
 *
 * Return: The index of the gap if found, otherwise an index outside the
 * range specified (in which case 'return - index >= max_scan' will be true).
 * In the rare case of index wrap-around, 0 will be returned.
 */
pgoff_t page_cache_next_miss(struct address_space *mapping,
                             pgoff_t index, unsigned long max_scan)
{
    XA_STATE(xas, &mapping->i_pages, index);

    while (max_scan--) {
        void *entry = xas_next(&xas);
        if (!entry || xa_is_value(entry))
            break;
        if (xas.xa_index == 0)
            break;
    }

    return xas.xa_index;
}
EXPORT_SYMBOL(page_cache_next_miss);

/*
 * Lock ordering:
 *
 *  ->i_mmap_rwsem      (truncate_pagecache)
 *    ->private_lock        (__free_pte->block_dirty_folio)
 *      ->swap_lock     (exclusive_swap_page, others)
 *        ->i_pages lock
 *
 *  ->i_rwsem
 *    ->invalidate_lock     (acquired by fs in truncate path)
 *      ->i_mmap_rwsem      (truncate->unmap_mapping_range)
 *
 *  ->mmap_lock
 *    ->i_mmap_rwsem
 *      ->page_table_lock or pte_lock   (various, mainly in memory.c)
 *        ->i_pages lock    (arch-dependent flush_dcache_mmap_lock)
 *
 *  ->mmap_lock
 *    ->invalidate_lock     (filemap_fault)
 *      ->lock_page     (filemap_fault, access_process_vm)
 *
 *  ->i_rwsem           (generic_perform_write)
 *    ->mmap_lock       (fault_in_readable->do_page_fault)
 *
 *  bdi->wb.list_lock
 *    sb_lock           (fs/fs-writeback.c)
 *    ->i_pages lock        (__sync_single_inode)
 *
 *  ->i_mmap_rwsem
 *    ->anon_vma.lock       (vma_adjust)
 *
 *  ->anon_vma.lock
 *    ->page_table_lock or pte_lock (anon_vma_prepare and various)
 *
 *  ->page_table_lock or pte_lock
 *    ->swap_lock       (try_to_unmap_one)
 *    ->private_lock        (try_to_unmap_one)
 *    ->i_pages lock        (try_to_unmap_one)
 *    ->lruvec->lru_lock    (follow_page->mark_page_accessed)
 *    ->lruvec->lru_lock    (check_pte_range->isolate_lru_page)
 *    ->private_lock        (page_remove_rmap->set_page_dirty)
 *    ->i_pages lock        (page_remove_rmap->set_page_dirty)
 *    bdi.wb->list_lock     (page_remove_rmap->set_page_dirty)
 *    ->inode->i_lock       (page_remove_rmap->set_page_dirty)
 *    ->memcg->move_lock    (page_remove_rmap->lock_page_memcg)
 *    bdi.wb->list_lock     (zap_pte_range->set_page_dirty)
 *    ->inode->i_lock       (zap_pte_range->set_page_dirty)
 *    ->private_lock        (zap_pte_range->block_dirty_folio)
 *
 * ->i_mmap_rwsem
 *   ->tasklist_lock            (memory_failure, collect_procs_ao)
 */
static void page_cache_delete(struct address_space *mapping,
                              struct folio *folio, void *shadow)
{
    XA_STATE(xas, &mapping->i_pages, folio->index);
    long nr = 1;

    mapping_set_update(&xas, mapping);

    /* hugetlb pages are represented by a single entry in the xarray */
    if (!folio_test_hugetlb(folio)) {
        xas_set_order(&xas, folio->index, folio_order(folio));
        nr = folio_nr_pages(folio);
    }

    VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

    xas_store(&xas, shadow);
    xas_init_marks(&xas);

    folio->mapping = NULL;
    /* Leave page->index set: truncation lookup relies upon it */
    mapping->nrpages -= nr;
}

/*
 * Delete a page from the page cache and free it. Caller has to make
 * sure the page is locked and that nobody else uses it - or that usage
 * is safe.  The caller must hold the i_pages lock.
 */
void __filemap_remove_folio(struct folio *folio, void *shadow)
{
    struct address_space *mapping = folio->mapping;

    filemap_unaccount_folio(mapping, folio);
    page_cache_delete(mapping, folio, shadow);
}

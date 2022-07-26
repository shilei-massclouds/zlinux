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
#if 0
#include <linux/swapops.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/error-injection.h>
#endif
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#if 0
#include <linux/pagevec.h>
#include <linux/security.h>
#include <linux/cpuset.h>
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/rmap.h>
#include <linux/delayacct.h>
#include <linux/psi.h>
#include <linux/page_idle.h>
#endif
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

#if 0
#include <asm/mman.h>
#endif

vm_fault_t filemap_map_pages(struct vm_fault *vmf,
                             pgoff_t start_pgoff, pgoff_t end_pgoff)
{
    panic("%s: END!\n", __func__);
}

/* This is used for a general mmap of a disk file */

int generic_file_mmap(struct file *file, struct vm_area_struct *vma)
{
#if 0
    struct address_space *mapping = file->f_mapping;

    if (!mapping->a_ops->readpage)
        return -ENOEXEC;
    file_accessed(file);
    vma->vm_ops = &generic_file_vm_ops;
#endif
    panic("%s: END!\n", __func__);
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

int filemap_write_and_wait_range(struct address_space *mapping,
                                 loff_t lstart, loff_t lend)
{
    int err = 0;

    if (mapping_needs_writeback(mapping)) {
        panic("%s: mapping_needs_writeback!\n", __func__);
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
    if (unlikely(ret))
        __folio_clear_locked(folio);
    else {
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

        panic("%s: folio a_ops(%lx) NULL!\n", __func__, mapping->a_ops);
        panic("%s: folio filler(%lx) NULL!\n", __func__, filler);
    }

    panic("%s: END!\n", __func__);
}

static struct page *
do_read_cache_page(struct address_space *mapping,
                   pgoff_t index, filler_t *filler, void *data, gfp_t gfp)
{
    struct folio *folio;

    folio = do_read_cache_folio(mapping, index, filler, data, gfp);
#if 0
    if (IS_ERR(folio))
        return &folio->page;
    return folio_file_page(folio, index);
#endif
    panic("%s: END!\n", __func__);
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

    panic("%s: folio(%lx) END!\n", __func__, folio);

 no_page:
    if (!folio && (fgp_flags & FGP_CREAT)) {
        panic("%s: FGP_CREAT!\n", __func__);
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
    panic("%s: END!\n", __func__);
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

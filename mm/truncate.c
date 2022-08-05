// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/truncate.c - code for taking down pages from address_spaces
 *
 * Copyright (C) 2002, Linus Torvalds
 *
 * 10Sep2002    Andrew Morton
 *      Initial version.
 */

#include <linux/kernel.h>
#include <linux/backing-dev.h>
#if 0
#include <linux/dax.h>
#endif
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/export.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/pagevec.h>
//#include <linux/task_io_accounting_ops.h>
#include <linux/buffer_head.h>  /* grr. try_to_release_page */
#include <linux/shmem_fs.h>
//#include <linux/rmap.h>
#include "internal.h"

/*
 * Unconditionally remove exceptional entries. Usually called from truncate
 * path. Note that the folio_batch may be altered by this function by removing
 * exceptional entries similar to what folio_batch_remove_exceptionals() does.
 */
static void
truncate_folio_batch_exceptionals(struct address_space *mapping,
                                  struct folio_batch *fbatch, pgoff_t *indices)
{
    int i, j;
    bool dax;

    /* Handled by shmem itself */
    if (shmem_mapping(mapping))
        return;

    for (j = 0; j < folio_batch_count(fbatch); j++)
        if (xa_is_value(fbatch->folios[j]))
            break;

    if (j == folio_batch_count(fbatch))
        return;

    panic("%s: END!\n", __func__);
}

/**
 * folio_invalidate - Invalidate part or all of a folio.
 * @folio: The folio which is affected.
 * @offset: start of the range to invalidate
 * @length: length of the range to invalidate
 *
 * folio_invalidate() is called when all or part of the folio has become
 * invalidated by a truncate operation.
 *
 * folio_invalidate() does not have to release all buffers, but it must
 * ensure that no dirty buffer is left outside @offset and that no I/O
 * is underway against any of the blocks which are outside the truncation
 * point.  Because the caller is about to free (and possibly reuse) those
 * blocks on-disk.
 */
void folio_invalidate(struct folio *folio, size_t offset, size_t length)
{
    const struct address_space_operations *aops = folio->mapping->a_ops;

    if (aops->invalidate_folio)
        aops->invalidate_folio(folio, offset, length);
}
EXPORT_SYMBOL_GPL(folio_invalidate);

/*
 * If truncate cannot remove the fs-private metadata from the page, the page
 * becomes orphaned.  It will be left on the LRU and may even be mapped into
 * user pagetables if we're racing with filemap_fault().
 *
 * We need to bail out if page->mapping is no longer equal to the original
 * mapping.  This happens a) when the VM reclaimed the page while we waited on
 * its lock, b) when a concurrent invalidate_mapping_pages got there first and
 * c) when tmpfs swizzles a page between a tmpfs inode and swapper_space.
 */
static void truncate_cleanup_folio(struct folio *folio)
{
    if (folio_mapped(folio))
        unmap_mapping_folio(folio);

    if (folio_has_private(folio))
        folio_invalidate(folio, 0, folio_size(folio));

    /*
     * Some filesystems seem to re-dirty the page even after
     * the VM has canceled the dirty bit (eg ext3 journaling).
     * Hence dirty accounting check is placed after invalidation.
     */
    folio_cancel_dirty(folio);
    folio_clear_mappedtodisk(folio);
}

/**
 * truncate_inode_pages_range - truncate range of pages specified by start & end byte offsets
 * @mapping: mapping to truncate
 * @lstart: offset from which to truncate
 * @lend: offset to which to truncate (inclusive)
 *
 * Truncate the page cache, removing the pages that are between
 * specified offsets (and zeroing out partial pages
 * if lstart or lend + 1 is not page aligned).
 *
 * Truncate takes two passes - the first pass is nonblocking.  It will not
 * block on page locks and it will not block on writeback.  The second pass
 * will wait.  This is to prevent as much IO as possible in the affected region.
 * The first pass will remove most pages, so the search cost of the second pass
 * is low.
 *
 * We pass down the cache-hot hint to the page freeing code.  Even if the
 * mapping is large, it is probably the case that the final pages are the most
 * recently touched, and freeing happens in ascending file offset order.
 *
 * Note that since ->invalidate_folio() accepts range to invalidate
 * truncate_inode_pages_range is able to handle cases where lend + 1 is not
 * page aligned properly.
 */
void truncate_inode_pages_range(struct address_space *mapping,
                                loff_t lstart, loff_t lend)
{
    pgoff_t     start;      /* inclusive */
    pgoff_t     end;        /* exclusive */
    pgoff_t     indices[PAGEVEC_SIZE];
    pgoff_t     index;
    int         i;
    bool        same_folio;
    struct folio *folio;
    struct folio_batch fbatch;

    if (mapping_empty(mapping))
        return;

    /*
     * 'start' and 'end' always covers the range of pages to be fully
     * truncated. Partial pages are covered with 'partial_start' at the
     * start of the range and 'partial_end' at the end of the range.
     * Note that 'end' is exclusive while 'lend' is inclusive.
     */
    start = (lstart + PAGE_SIZE - 1) >> PAGE_SHIFT;
    if (lend == -1)
        /*
         * lend == -1 indicates end-of-file so we have to set 'end'
         * to the highest possible pgoff_t and since the type is
         * unsigned we're using -1.
         */
        end = -1;
    else
        end = (lend + 1) >> PAGE_SHIFT;

    folio_batch_init(&fbatch);
    index = start;
    while (index < end &&
           find_lock_entries(mapping, index, end - 1, &fbatch, indices)) {
        index = indices[folio_batch_count(&fbatch) - 1] + 1;
        truncate_folio_batch_exceptionals(mapping, &fbatch, indices);
        for (i = 0; i < folio_batch_count(&fbatch); i++)
            truncate_cleanup_folio(fbatch.folios[i]);
        delete_from_page_cache_batch(mapping, &fbatch);
        for (i = 0; i < folio_batch_count(&fbatch); i++)
            folio_unlock(fbatch.folios[i]);
        folio_batch_release(&fbatch);
        cond_resched();
    }

    same_folio = (lstart >> PAGE_SHIFT) == (lend >> PAGE_SHIFT);
    folio = __filemap_get_folio(mapping, lstart >> PAGE_SHIFT, FGP_LOCK, 0);
    if (folio) {
#if 0
        same_folio = lend < folio_pos(folio) + folio_size(folio);
        if (!truncate_inode_partial_folio(folio, lstart, lend)) {
            start = folio->index + folio_nr_pages(folio);
            if (same_folio)
                end = folio->index;
        }
        folio_unlock(folio);
        folio_put(folio);
        folio = NULL;
#endif
        panic("%s: 1 folio!\n", __func__);
    }

    if (!same_folio)
        folio = __filemap_get_folio(mapping, lend >> PAGE_SHIFT, FGP_LOCK, 0);
    if (folio) {
#if 0
        if (!truncate_inode_partial_folio(folio, lstart, lend))
            end = folio->index;
        folio_unlock(folio);
        folio_put(folio);
#endif
        panic("%s: 2 folio!\n", __func__);
    }

    index = start;
    while (index < end) {
        cond_resched();
        if (!find_get_entries(mapping, index, end - 1, &fbatch, indices)) {
            /* If all gone from start onwards, we're done */
            if (index == start)
                break;
            /* Otherwise restart to make sure all gone */
            index = start;
            continue;
        }

        for (i = 0; i < folio_batch_count(&fbatch); i++) {
            struct folio *folio = fbatch.folios[i];

            /* We rely upon deletion not changing page->index */
            index = indices[i];

            if (xa_is_value(folio))
                continue;

#if 0
            folio_lock(folio);
            VM_BUG_ON_FOLIO(!folio_contains(folio, index), folio);
            folio_wait_writeback(folio);
            truncate_inode_folio(mapping, folio);
            folio_unlock(folio);
            index = folio_index(folio) + folio_nr_pages(folio) - 1;
#endif
            panic("%s: 1!\n", __func__);
        }
        truncate_folio_batch_exceptionals(mapping, &fbatch, indices);
        folio_batch_release(&fbatch);
        index++;
    }
}
EXPORT_SYMBOL(truncate_inode_pages_range);

/**
 * truncate_inode_pages - truncate *all* the pages from an offset
 * @mapping: mapping to truncate
 * @lstart: offset from which to truncate
 *
 * Called under (and serialised by) inode->i_rwsem and
 * mapping->invalidate_lock.
 *
 * Note: When this function returns, there can be a page in the process of
 * deletion (inside __delete_from_page_cache()) in the specified range.  Thus
 * mapping->nrpages can be non-zero when this function returns even after
 * truncation of the whole mapping.
 */
void truncate_inode_pages(struct address_space *mapping, loff_t lstart)
{
    truncate_inode_pages_range(mapping, lstart, (loff_t)-1);
}
EXPORT_SYMBOL(truncate_inode_pages);

/*
 * Used to get rid of pages on hardware memory corruption.
 */
int generic_error_remove_page(struct address_space *mapping, struct page *page)
{
#if 0
    VM_BUG_ON_PAGE(PageTail(page), page);

    if (!mapping)
        return -EINVAL;
    /*
     * Only punch for normal data pages for now.
     * Handling other types like directories would need more auditing.
     */
    if (!S_ISREG(mapping->host->i_mode))
        return -EIO;
    return truncate_inode_folio(mapping, page_folio(page));
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(generic_error_remove_page);

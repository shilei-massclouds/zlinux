// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/readahead.c - address_space-level file readahead.
 *
 * Copyright (C) 2002, Linus Torvalds
 *
 * 09Apr2002    Andrew Morton
 *      Initial version.
 */

/**
 * DOC: Readahead Overview
 *
 * Readahead is used to read content into the page cache before it is
 * explicitly requested by the application.  Readahead only ever
 * attempts to read folios that are not yet in the page cache.  If a
 * folio is present but not up-to-date, readahead will not try to read
 * it. In that case a simple ->readpage() will be requested.
 *
 * Readahead is triggered when an application read request (whether a
 * system call or a page fault) finds that the requested folio is not in
 * the page cache, or that it is in the page cache and has the
 * readahead flag set.  This flag indicates that the folio was read
 * as part of a previous readahead request and now that it has been
 * accessed, it is time for the next readahead.
 *
 * Each readahead request is partly synchronous read, and partly async
 * readahead.  This is reflected in the struct file_ra_state which
 * contains ->size being the total number of pages, and ->async_size
 * which is the number of pages in the async section.  The readahead
 * flag will be set on the first folio in this async section to trigger
 * a subsequent readahead.  Once a series of sequential reads has been
 * established, there should be no need for a synchronous component and
 * all readahead request will be fully asynchronous.
 *
 * When either of the triggers causes a readahead, three numbers need
 * to be determined: the start of the region to read, the size of the
 * region, and the size of the async tail.
 *
 * The start of the region is simply the first page address at or after
 * the accessed address, which is not currently populated in the page
 * cache.  This is found with a simple search in the page cache.
 *
 * The size of the async tail is determined by subtracting the size that
 * was explicitly requested from the determined request size, unless
 * this would be less than zero - then zero is used.  NOTE THIS
 * CALCULATION IS WRONG WHEN THE START OF THE REGION IS NOT THE ACCESSED
 * PAGE.  ALSO THIS CALCULATION IS NOT USED CONSISTENTLY.
 *
 * The size of the region is normally determined from the size of the
 * previous readahead which loaded the preceding pages.  This may be
 * discovered from the struct file_ra_state for simple sequential reads,
 * or from examining the state of the page cache when multiple
 * sequential reads are interleaved.  Specifically: where the readahead
 * was triggered by the readahead flag, the size of the previous
 * readahead is assumed to be the number of pages from the triggering
 * page to the start of the new readahead.  In these cases, the size of
 * the previous readahead is scaled, often doubled, for the new
 * readahead, though see get_next_ra_size() for details.
 *
 * If the size of the previous read cannot be determined, the number of
 * preceding pages in the page cache is used to estimate the size of
 * a previous read.  This estimate could easily be misled by random
 * reads being coincidentally adjacent, so it is ignored unless it is
 * larger than the current request, and it is not scaled up, unless it
 * is at the start of file.
 *
 * In general readahead is accelerated at the start of the file, as
 * reads from there are often sequential.  There are other minor
 * adjustments to the readahead size in various special cases and these
 * are best discovered by reading the code.
 *
 * The above calculation, based on the previous readahead size,
 * determines the size of the readahead, to which any requested read
 * size may be added.
 *
 * Readahead requests are sent to the filesystem using the ->readahead()
 * address space operation, for which mpage_readahead() is a canonical
 * implementation.  ->readahead() should normally initiate reads on all
 * folios, but may fail to read any or all folios without causing an I/O
 * error.  The page cache reading code will issue a ->readpage() request
 * for any folio which ->readahead() did not read, and only an error
 * from this will be final.
 *
 * ->readahead() will generally call readahead_folio() repeatedly to get
 * each folio from those prepared for readahead.  It may fail to read a
 * folio by:
 *
 * * not calling readahead_folio() sufficiently many times, effectively
 *   ignoring some folios, as might be appropriate if the path to
 *   storage is congested.
 *
 * * failing to actually submit a read request for a given folio,
 *   possibly due to insufficient resources, or
 *
 * * getting an error during subsequent processing of a request.
 *
 * In the last two cases, the folio should be unlocked by the filesystem
 * to indicate that the read attempt has failed.  In the first case the
 * folio will be unlocked by the VFS.
 *
 * Those folios not in the final ``async_size`` of the request should be
 * considered to be important and ->readahead() should not fail them due
 * to congestion or temporary resource unavailability, but should wait
 * for necessary resources (e.g.  memory or indexing information) to
 * become available.  Folios in the final ``async_size`` may be
 * considered less urgent and failure to read them is more acceptable.
 * In this case it is best to use filemap_remove_folio() to remove the
 * folios from the page cache as is automatically done for folios that
 * were not fetched with readahead_folio().  This will allow a
 * subsequent synchronous readahead request to try them again.  If they
 * are left in the page cache, then they will be read individually using
 * ->readpage() which may be less efficient.
 */
#include <linux/kernel.h>
//#include <linux/dax.h>
#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/backing-dev.h>
//#include <linux/task_io_accounting_ops.h>
#include <linux/pagevec.h>
#include <linux/pagemap.h>
//#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/mm_inline.h>
//#include <linux/blk-cgroup.h>
//#include <linux/fadvise.h>
#include <linux/sched/mm.h>

#include "internal.h"

/*
 * Initialise a struct file's readahead state.  Assumes that the caller has
 * memset *ra to zero.
 */
void
file_ra_state_init(struct file_ra_state *ra, struct address_space *mapping)
{
    ra->ra_pages = inode_to_bdi(mapping->host)->ra_pages;
    ra->prev_pos = -1;
}
EXPORT_SYMBOL_GPL(file_ra_state_init);

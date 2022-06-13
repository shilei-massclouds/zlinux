// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/percpu-vm.c - vmalloc area based chunk allocation
 *
 * Copyright (C) 2010       SUSE Linux Products GmbH
 * Copyright (C) 2010       Tejun Heo <tj@kernel.org>
 *
 * Chunks are mapped into vmalloc areas and populated page by page.
 * This is the default chunk allocator.
 */
#include "internal.h"

static int __init pcpu_verify_alloc_info(const struct pcpu_alloc_info *ai)
{
    /* no extra restriction */
    return 0;
}

static struct pcpu_chunk *pcpu_create_chunk(gfp_t gfp)
{
    panic("%s: NO implementation!\n", __func__);
}

/**
 * pcpu_populate_chunk - populate and map an area of a pcpu_chunk
 * @chunk: chunk of interest
 * @page_start: the start page
 * @page_end: the end page
 * @gfp: allocation flags passed to the underlying memory allocator
 *
 * For each cpu, populate and map pages [@page_start,@page_end) into
 * @chunk.
 *
 * CONTEXT:
 * pcpu_alloc_mutex, does GFP_KERNEL allocation.
 */
static int pcpu_populate_chunk(struct pcpu_chunk *chunk,
                               int page_start, int page_end, gfp_t gfp)
{
    panic("%s: NO implementation!\n", __func__);
}

static struct page *pcpu_addr_to_page(void *addr)
{
    panic("%s: NO implementation!\n", __func__);
    //return vmalloc_to_page(addr);
}

/**
 * pcpu_should_reclaim_chunk - determine if a chunk should go into reclaim
 * @chunk: chunk of interest
 *
 * This is the entry point for percpu reclaim.  If a chunk qualifies, it is then
 * isolated and managed in separate lists at the back of pcpu_slot: sidelined
 * and to_depopulate respectively.  The to_depopulate list holds chunks slated
 * for depopulation.  They no longer contribute to pcpu_nr_empty_pop_pages once
 * they are on this list.  Once depopulated, they are moved onto the sidelined
 * list which enables them to be pulled back in for allocation if no other chunk
 * can suffice the allocation.
 */
static bool pcpu_should_reclaim_chunk(struct pcpu_chunk *chunk)
{
    /* do not reclaim either the first chunk or reserved chunk */
    if (chunk == pcpu_first_chunk || chunk == pcpu_reserved_chunk)
        return false;

    /*
     * If it is isolated, it may be on the sidelined list so move it back to
     * the to_depopulate list.  If we hit at least 1/4 pages empty pages AND
     * there is no system-wide shortage of empty pages aside from this
     * chunk, move it to the to_depopulate list.
     */
    return ((chunk->isolated && chunk->nr_empty_pop_pages) ||
            (pcpu_nr_empty_pop_pages >
             (PCPU_EMPTY_POP_PAGES_HIGH + chunk->nr_empty_pop_pages) &&
             chunk->nr_empty_pop_pages >= chunk->nr_pages / 4));
}

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

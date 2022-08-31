// SPDX-License-Identifier: GPL-2.0-only
/*
 * Dynamic DMA mapping support.
 *
 * This implementation is a fallback for platforms that do not support
 * I/O TLBs (aka DMA address translation hardware).
 * Copyright (C) 2000 Asit Mallick <Asit.K.Mallick@intel.com>
 * Copyright (C) 2000 Goutham Rao <goutham.rao@intel.com>
 * Copyright (C) 2000, 2003 Hewlett-Packard Co
 *  David Mosberger-Tang <davidm@hpl.hp.com>
 *
 * 03/05/07 davidm  Switch from PCI-DMA to generic device DMA API.
 * 00/12/13 davidm  Rename to swiotlb.c and add mark_clean() to avoid
 *          unnecessary i-cache flushing.
 * 04/07/.. ak      Better overflow handling. Assorted fixes.
 * 05/09/10 linville    Add support for syncing ranges, support syncing for
 *          DMA_BIDIRECTIONAL mappings, miscellaneous cleanup.
 * 08/12/11 beckyb  Add highmem support
 */

#define pr_fmt(fmt) "software IO TLB: " fmt

#include <linux/cache.h>
//#include <linux/cc_platform.h>
#include <linux/ctype.h>
#if 0
#include <linux/debugfs.h>
#include <linux/dma-direct.h>
#include <linux/dma-map-ops.h>
#endif
#include <linux/export.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/io.h>
//#include <linux/iommu-helper.h>
#include <linux/init.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/pfn.h>
#include <linux/scatterlist.h>
#include <linux/set_memory.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/swiotlb.h>
#include <linux/types.h>

enum swiotlb_force swiotlb_force;

/*
 * Statically reserve bounce buffer space and initialize bounce buffer data
 * structures for the software IO TLB used to implement the DMA API.
 */
void  __init
swiotlb_init(int verbose)
{
    panic("%s: NO implementation!\n", __func__);
}

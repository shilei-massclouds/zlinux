// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018-2020 Christoph Hellwig.
 *
 * DMA operations that map physical memory directly without using an IOMMU.
 */
#include <linux/memblock.h> /* for max_pfn */
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/dma-map-ops.h>
#if 0
#include <linux/scatterlist.h>
#endif
#include <linux/pfn.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include "direct.h"

int dma_direct_supported(struct device *dev, u64 mask)
{
    u64 min_mask = (max_pfn - 1) << PAGE_SHIFT;

    /*
     * Because 32-bit DMA masks are so common we expect every architecture
     * to be able to satisfy them - either by not supporting more physical
     * memory, or by providing a ZONE_DMA32.  If neither is the case, the
     * architecture needs to use an IOMMU instead of the direct mapping.
     */
    if (mask >= DMA_BIT_MASK(32))
        return 1;

    /*
     * This check needs to be against the actual bit mask value, so use
     * phys_to_dma_unencrypted() here so that the SME encryption mask isn't
     * part of the check.
     */
    return mask >= phys_to_dma_unencrypted(dev, min_mask);
}

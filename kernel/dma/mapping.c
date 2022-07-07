/*
 * arch-independent dma-mapping routines
 *
 * Copyright (c) 2006  SUSE Linux Products GmbH
 * Copyright (c) 2006  Tejun Heo <teheo@suse.de>
 */
#include <linux/memblock.h> /* for max_pfn */
#include <linux/dma-map-ops.h>
#include <linux/export.h>
#include <linux/gfp.h>
#include <linux/of_device.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "direct.h"

#define arch_dma_set_mask(dev, mask)    do { } while (0)

int dma_supported(struct device *dev, u64 mask)
{
    /*
     * ->dma_supported sets the bypass flag, so we must always call
     * into the method here unless the device is truly direct mapped.
     */
    return dma_direct_supported(dev, mask);
}
EXPORT_SYMBOL(dma_supported);

int dma_set_mask(struct device *dev, u64 mask)
{
    /*
     * Truncate the mask to the actually supported dma_addr_t width to
     * avoid generating unsupportable addresses.
     */
    mask = (dma_addr_t)mask;

    if (!dev->dma_mask || !dma_supported(dev, mask))
        return -EIO;

    arch_dma_set_mask(dev, mask);
    *dev->dma_mask = mask;
    return 0;
}
EXPORT_SYMBOL(dma_set_mask);

int dma_set_coherent_mask(struct device *dev, u64 mask)
{
    /*
     * Truncate the mask to the actually supported dma_addr_t width to
     * avoid generating unsupportable addresses.
     */
    mask = (dma_addr_t)mask;

    if (!dma_supported(dev, mask))
        return -EIO;

    dev->coherent_dma_mask = mask;
    return 0;
}
EXPORT_SYMBOL(dma_set_coherent_mask);

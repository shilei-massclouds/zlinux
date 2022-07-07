/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Internals of the DMA direct mapping implementation.  Only for use by the
 * DMA mapping code and IOMMU drivers.
 */
#ifndef _LINUX_DMA_DIRECT_H
#define _LINUX_DMA_DIRECT_H 1

#include <linux/dma-mapping.h>
#include <linux/dma-map-ops.h>
#include <linux/memblock.h> /* for min_low_pfn */
#if 0
#include <linux/mem_encrypt.h>
#endif
#include <linux/swiotlb.h>

extern unsigned int zone_dma_bits;

/*
 * Record the mapping of CPU physical to DMA addresses for a given region.
 */
struct bus_dma_region {
    phys_addr_t cpu_start;
    dma_addr_t  dma_start;
    u64     size;
    u64     offset;
};

int dma_direct_supported(struct device *dev, u64 mask);

static inline dma_addr_t
translate_phys_to_dma(struct device *dev, phys_addr_t paddr)
{
    panic("%s: NO implementation!\n", __func__);
}

static inline dma_addr_t
phys_to_dma_unencrypted(struct device *dev, phys_addr_t paddr)
{
    if (dev->dma_range_map)
        return translate_phys_to_dma(dev, paddr);
    return paddr;
}

#endif /* _LINUX_DMA_DIRECT_H */

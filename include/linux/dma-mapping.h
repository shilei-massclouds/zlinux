/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_DMA_MAPPING_H
#define _LINUX_DMA_MAPPING_H

#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/err.h>
#if 0
#include <linux/dma-direction.h>
#include <linux/scatterlist.h>
#include <linux/mem_encrypt.h>
#endif
#include <linux/bug.h>

#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))

int dma_supported(struct device *dev, u64 mask);
int dma_set_mask(struct device *dev, u64 mask);
int dma_set_coherent_mask(struct device *dev, u64 mask);

/*
 * Set both the DMA mask and the coherent DMA mask to the same thing.
 * Note that we don't check the return value from dma_set_coherent_mask()
 * as the DMA API guarantees that the coherent DMA mask can be set to
 * the same or smaller than the streaming DMA mask.
 */
static inline int dma_set_mask_and_coherent(struct device *dev, u64 mask)
{
    int rc = dma_set_mask(dev, mask);
    if (rc == 0)
        dma_set_coherent_mask(dev, mask);
    return rc;
}

#endif /* _LINUX_DMA_MAPPING_H */

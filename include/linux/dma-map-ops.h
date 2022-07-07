/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This header is for implementations of dma_map_ops and related code.
 * It should not be included in drivers just using the DMA API.
 */
#ifndef _LINUX_DMA_MAP_OPS_H
#define _LINUX_DMA_MAP_OPS_H

#include <linux/dma-mapping.h>
#include <linux/pgtable.h>

struct dma_map_ops {
};

static inline const struct dma_map_ops *get_dma_ops(struct device *dev)
{
    return NULL;
}

static inline void set_dma_ops(struct device *dev,
                               const struct dma_map_ops *dma_ops)
{
}

#endif /* _LINUX_DMA_MAP_OPS_H */

/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2004 - 2006 Intel Corporation. All rights reserved.
 */
#ifndef LINUX_DMAENGINE_H
#define LINUX_DMAENGINE_H

#include <linux/device.h>
#include <linux/err.h>
#include <linux/uio.h>
#include <linux/bug.h>
#include <linux/scatterlist.h>
#include <linux/bitmap.h>
#include <linux/types.h>
#include <asm/page.h>

/**
 * typedef dma_cookie_t - an opaque DMA cookie
 *
 * if dma_cookie_t is >0 it's a DMA request cookie, <0 it's an error code
 */
typedef s32 dma_cookie_t;
#define DMA_MIN_COOKIE  1

/**
 * enum dma_transfer_direction - dma transfer mode and direction indicator
 * @DMA_MEM_TO_MEM: Async/Memcpy mode
 * @DMA_MEM_TO_DEV: Slave mode & From Memory to Device
 * @DMA_DEV_TO_MEM: Slave mode & From Device to Memory
 * @DMA_DEV_TO_DEV: Slave mode & From Device to Device
 */
enum dma_transfer_direction {
    DMA_MEM_TO_MEM,
    DMA_MEM_TO_DEV,
    DMA_DEV_TO_MEM,
    DMA_DEV_TO_DEV,
    DMA_TRANS_NONE,
};

/**
 * struct dma_chan_dev - relate sysfs device node to backing channel device
 * @chan: driver channel device
 * @device: sysfs device
 * @dev_id: parent dma_device dev_id
 * @chan_dma_dev: The channel is using custom/different dma-mapping
 * compared to the parent dma_device
 */
struct dma_chan_dev {
    struct dma_chan *chan;
    struct device device;
    int dev_id;
    bool chan_dma_dev;
};

/**
 * enum dma_slave_buswidth - defines bus width of the DMA slave
 * device, source or target buses
 */
enum dma_slave_buswidth {
    DMA_SLAVE_BUSWIDTH_UNDEFINED = 0,
    DMA_SLAVE_BUSWIDTH_1_BYTE = 1,
    DMA_SLAVE_BUSWIDTH_2_BYTES = 2,
    DMA_SLAVE_BUSWIDTH_3_BYTES = 3,
    DMA_SLAVE_BUSWIDTH_4_BYTES = 4,
    DMA_SLAVE_BUSWIDTH_8_BYTES = 8,
    DMA_SLAVE_BUSWIDTH_16_BYTES = 16,
    DMA_SLAVE_BUSWIDTH_32_BYTES = 32,
    DMA_SLAVE_BUSWIDTH_64_BYTES = 64,
    DMA_SLAVE_BUSWIDTH_128_BYTES = 128,
};

struct dma_slave_config {
    enum dma_transfer_direction direction;
    phys_addr_t src_addr;
    phys_addr_t dst_addr;
    enum dma_slave_buswidth src_addr_width;
    enum dma_slave_buswidth dst_addr_width;
    u32 src_maxburst;
    u32 dst_maxburst;
    u32 src_port_window_size;
    u32 dst_port_window_size;
    bool device_fc;
    void *peripheral_config;
    size_t peripheral_size;
};

/**
 * typedef dma_filter_fn - callback filter for dma_request_channel
 * @chan: channel to be reviewed
 * @filter_param: opaque parameter passed through dma_request_channel
 *
 * When this optional parameter is specified in a call to dma_request_channel a
 * suitable channel is passed to this routine for further dispositioning before
 * being returned.  Where 'suitable' indicates a non-busy channel that
 * satisfies the given capability mask.  It returns 'true' to indicate that the
 * channel is suitable.
 */
typedef bool (*dma_filter_fn)(struct dma_chan *chan,
                              void *filter_param);

#endif /* DMAENGINE_H */

// SPDX-License-Identifier: GPL-2.0
/*
 * Functions related to setting various queue properties from drivers
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/pagemap.h>
#include <linux/backing-dev-defs.h>
#if 0
#include <linux/gcd.h>
#include <linux/lcm.h>
#endif
#include <linux/jiffies.h>
#include <linux/gfp.h>
#include <linux/dma-mapping.h>

#include "blk.h"
#if 0
#include "blk-wbt.h"
#endif

/**
 * blk_queue_write_cache - configure queue's write cache
 * @q:      the request queue for the device
 * @wc:     write back cache on or off
 * @fua:    device supports FUA writes, if true
 *
 * Tell the block layer about the write cache of @q.
 */
void blk_queue_write_cache(struct request_queue *q, bool wc, bool fua)
{
    if (wc)
        blk_queue_flag_set(QUEUE_FLAG_WC, q);
    else
        blk_queue_flag_clear(QUEUE_FLAG_WC, q);
    if (fua)
        blk_queue_flag_set(QUEUE_FLAG_FUA, q);
    else
        blk_queue_flag_clear(QUEUE_FLAG_FUA, q);
}
EXPORT_SYMBOL_GPL(blk_queue_write_cache);

/**
 * blk_queue_max_segments - set max hw segments for a request for this queue
 * @q:  the request queue for the device
 * @max_segments:  max number of segments
 *
 * Description:
 *    Enables a low level driver to set an upper limit on the number of
 *    hw data segments in a request.
 **/
void blk_queue_max_segments(struct request_queue *q,
                            unsigned short max_segments)
{
    if (!max_segments) {
        max_segments = 1;
        printk(KERN_INFO "%s: set to minimum %d\n", __func__, max_segments);
    }

    q->limits.max_segments = max_segments;
}
EXPORT_SYMBOL(blk_queue_max_segments);

/**
 * blk_queue_max_hw_sectors - set max sectors for a request for this queue
 * @q:  the request queue for the device
 * @max_hw_sectors:  max hardware sectors in the usual 512b unit
 *
 * Description:
 *    Enables a low level driver to set a hard upper limit,
 *    max_hw_sectors, on the size of requests.  max_hw_sectors is set by
 *    the device driver based upon the capabilities of the I/O
 *    controller.
 *
 *    max_dev_sectors is a hard limit imposed by the storage device for
 *    READ/WRITE requests. It is set by the disk driver.
 *
 *    max_sectors is a soft limit imposed by the block layer for
 *    filesystem type requests.  This value can be overridden on a
 *    per-device basis in /sys/block/<device>/queue/max_sectors_kb.
 *    The soft limit can not exceed max_hw_sectors.
 **/
void blk_queue_max_hw_sectors(struct request_queue *q,
                              unsigned int max_hw_sectors)
{
    struct queue_limits *limits = &q->limits;
    unsigned int max_sectors;

    if ((max_hw_sectors << 9) < PAGE_SIZE) {
        max_hw_sectors = 1 << (PAGE_SHIFT - 9);
        printk(KERN_INFO "%s: set to minimum %d\n",
               __func__, max_hw_sectors);
    }

    max_hw_sectors = round_down(max_hw_sectors,
                                limits->logical_block_size >> SECTOR_SHIFT);
    limits->max_hw_sectors = max_hw_sectors;

    max_sectors = min_not_zero(max_hw_sectors, limits->max_dev_sectors);
    max_sectors = min_t(unsigned int, max_sectors, BLK_DEF_MAX_SECTORS);
    max_sectors = round_down(max_sectors,
                             limits->logical_block_size >> SECTOR_SHIFT);
    limits->max_sectors = max_sectors;

    if (!q->disk)
        return;
    q->disk->bdi->io_pages = max_sectors >> (PAGE_SHIFT - 9);
}
EXPORT_SYMBOL(blk_queue_max_hw_sectors);

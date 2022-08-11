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

/**
 * blk_queue_max_segment_size - set max segment size for blk_rq_map_sg
 * @q:  the request queue for the device
 * @max_size:  max size of segment in bytes
 *
 * Description:
 *    Enables a low level driver to set an upper limit on the size of a
 *    coalesced segment
 **/
void blk_queue_max_segment_size(struct request_queue *q, unsigned int max_size)
{
    if (max_size < PAGE_SIZE) {
        max_size = PAGE_SIZE;
        printk(KERN_INFO "%s: set to minimum %d\n", __func__, max_size);
    }

    /* see blk_queue_virt_boundary() for the explanation */
    WARN_ON_ONCE(q->limits.virt_boundary_mask);

    q->limits.max_segment_size = max_size;
}
EXPORT_SYMBOL(blk_queue_max_segment_size);

/**
 * blk_queue_logical_block_size - set logical block size for the queue
 * @q:  the request queue for the device
 * @size:  the logical block size, in bytes
 *
 * Description:
 *   This should be set to the lowest possible block size that the
 *   storage device can address.  The default of 512 covers most
 *   hardware.
 **/
void blk_queue_logical_block_size(struct request_queue *q, unsigned int size)
{
    struct queue_limits *limits = &q->limits;

    limits->logical_block_size = size;

    if (limits->physical_block_size < size)
        limits->physical_block_size = size;

    if (limits->io_min < limits->physical_block_size)
        limits->io_min = limits->physical_block_size;

    limits->max_hw_sectors =
        round_down(limits->max_hw_sectors, size >> SECTOR_SHIFT);
    limits->max_sectors =
        round_down(limits->max_sectors, size >> SECTOR_SHIFT);
}
EXPORT_SYMBOL(blk_queue_logical_block_size);

/**
 * blk_queue_physical_block_size - set physical block size for the queue
 * @q:  the request queue for the device
 * @size:  the physical block size, in bytes
 *
 * Description:
 *   This should be set to the lowest possible sector size that the
 *   hardware can operate on without reverting to read-modify-write
 *   operations.
 */
void blk_queue_physical_block_size(struct request_queue *q, unsigned int size)
{
    q->limits.physical_block_size = size;

    if (q->limits.physical_block_size < q->limits.logical_block_size)
        q->limits.physical_block_size = q->limits.logical_block_size;

    if (q->limits.io_min < q->limits.physical_block_size)
        q->limits.io_min = q->limits.physical_block_size;
}
EXPORT_SYMBOL(blk_queue_physical_block_size);

/**
 * blk_queue_alignment_offset - set physical block alignment offset
 * @q:  the request queue for the device
 * @offset: alignment offset in bytes
 *
 * Description:
 *   Some devices are naturally misaligned to compensate for things like
 *   the legacy DOS partition table 63-sector offset.  Low-level drivers
 *   should call this function for devices whose first sector is not
 *   naturally aligned.
 */
void blk_queue_alignment_offset(struct request_queue *q, unsigned int offset)
{
    q->limits.alignment_offset = offset & (q->limits.physical_block_size - 1);
    q->limits.misaligned = 0;
}
EXPORT_SYMBOL(blk_queue_alignment_offset);

/**
 * blk_limits_io_min - set minimum request size for a device
 * @limits: the queue limits
 * @min:  smallest I/O size in bytes
 *
 * Description:
 *   Some devices have an internal block size bigger than the reported
 *   hardware sector size.  This function can be used to signal the
 *   smallest I/O the device can perform without incurring a performance
 *   penalty.
 */
void blk_limits_io_min(struct queue_limits *limits, unsigned int min)
{
    limits->io_min = min;

    if (limits->io_min < limits->logical_block_size)
        limits->io_min = limits->logical_block_size;

    if (limits->io_min < limits->physical_block_size)
        limits->io_min = limits->physical_block_size;
}
EXPORT_SYMBOL(blk_limits_io_min);

/**
 * blk_queue_io_min - set minimum request size for the queue
 * @q:  the request queue for the device
 * @min:  smallest I/O size in bytes
 *
 * Description:
 *   Storage devices may report a granularity or preferred minimum I/O
 *   size which is the smallest request the device can perform without
 *   incurring a performance penalty.  For disk drives this is often the
 *   physical block size.  For RAID arrays it is often the stripe chunk
 *   size.  A properly aligned multiple of minimum_io_size is the
 *   preferred request size for workloads where a high number of I/O
 *   operations is desired.
 */
void blk_queue_io_min(struct request_queue *q, unsigned int min)
{
    blk_limits_io_min(&q->limits, min);
}
EXPORT_SYMBOL(blk_queue_io_min);

/**
 * blk_limits_io_opt - set optimal request size for a device
 * @limits: the queue limits
 * @opt:  smallest I/O size in bytes
 *
 * Description:
 *   Storage devices may report an optimal I/O size, which is the
 *   device's preferred unit for sustained I/O.  This is rarely reported
 *   for disk drives.  For RAID arrays it is usually the stripe width or
 *   the internal track size.  A properly aligned multiple of
 *   optimal_io_size is the preferred request size for workloads where
 *   sustained throughput is desired.
 */
void blk_limits_io_opt(struct queue_limits *limits, unsigned int opt)
{
    limits->io_opt = opt;
}
EXPORT_SYMBOL(blk_limits_io_opt);

/**
 * blk_queue_io_opt - set optimal request size for the queue
 * @q:  the request queue for the device
 * @opt:  optimal request size in bytes
 *
 * Description:
 *   Storage devices may report an optimal I/O size, which is the
 *   device's preferred unit for sustained I/O.  This is rarely reported
 *   for disk drives.  For RAID arrays it is usually the stripe width or
 *   the internal track size.  A properly aligned multiple of
 *   optimal_io_size is the preferred request size for workloads where
 *   sustained throughput is desired.
 */
void blk_queue_io_opt(struct request_queue *q, unsigned int opt)
{
    blk_limits_io_opt(&q->limits, opt);
    if (!q->disk)
        return;
    q->disk->bdi->ra_pages =
        max(queue_io_opt(q) * 2 / PAGE_SIZE, VM_READAHEAD_PAGES);
}
EXPORT_SYMBOL(blk_queue_io_opt);

/**
 * blk_queue_max_discard_sectors - set max sectors for a single discard
 * @q:  the request queue for the device
 * @max_discard_sectors: maximum number of sectors to discard
 **/
void blk_queue_max_discard_sectors(struct request_queue *q,
                                   unsigned int max_discard_sectors)
{
    q->limits.max_hw_discard_sectors = max_discard_sectors;
    q->limits.max_discard_sectors = max_discard_sectors;
}
EXPORT_SYMBOL(blk_queue_max_discard_sectors);

/**
 * blk_queue_max_discard_segments - set max segments for discard requests
 * @q:  the request queue for the device
 * @max_segments:  max number of segments
 *
 * Description:
 *    Enables a low level driver to set an upper limit on the number of
 *    segments in a discard request.
 **/
void blk_queue_max_discard_segments(struct request_queue *q,
                                    unsigned short max_segments)
{
    q->limits.max_discard_segments = max_segments;
}
EXPORT_SYMBOL_GPL(blk_queue_max_discard_segments);

/**
 * blk_queue_max_write_zeroes_sectors - set max sectors for a single
 *                                      write zeroes
 * @q:  the request queue for the device
 * @max_write_zeroes_sectors: maximum number of sectors to write per command
 **/
void blk_queue_max_write_zeroes_sectors(struct request_queue *q,
        unsigned int max_write_zeroes_sectors)
{
    q->limits.max_write_zeroes_sectors = max_write_zeroes_sectors;
}
EXPORT_SYMBOL(blk_queue_max_write_zeroes_sectors);

/**
 * blk_set_default_limits - reset limits to default values
 * @lim:  the queue_limits structure to reset
 *
 * Description:
 *   Returns a queue_limit struct to its default state.
 */
void blk_set_default_limits(struct queue_limits *lim)
{
    lim->max_segments = BLK_MAX_SEGMENTS;
    lim->max_discard_segments = 1;
    lim->max_integrity_segments = 0;
    lim->seg_boundary_mask = BLK_SEG_BOUNDARY_MASK;
    lim->virt_boundary_mask = 0;
    lim->max_segment_size = BLK_MAX_SEGMENT_SIZE;
    lim->max_sectors = lim->max_hw_sectors = BLK_SAFE_MAX_SECTORS;
    lim->max_dev_sectors = 0;
    lim->chunk_sectors = 0;
    lim->max_write_zeroes_sectors = 0;
    lim->max_zone_append_sectors = 0;
    lim->max_discard_sectors = 0;
    lim->max_hw_discard_sectors = 0;
    lim->discard_granularity = 0;
    lim->discard_alignment = 0;
    lim->discard_misaligned = 0;
    lim->logical_block_size = lim->physical_block_size = lim->io_min = 512;
    lim->bounce = BLK_BOUNCE_NONE;
    lim->alignment_offset = 0;
    lim->io_opt = 0;
    lim->misaligned = 0;
    lim->zoned = BLK_ZONED_NONE;
    lim->zone_write_granularity = 0;
}
EXPORT_SYMBOL(blk_set_default_limits);

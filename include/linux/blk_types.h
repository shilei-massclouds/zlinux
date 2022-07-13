/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Block data types and constants.  Directly include this file only to
 * break include dependency loop.
 */
#ifndef __LINUX_BLK_TYPES_H
#define __LINUX_BLK_TYPES_H

#include <linux/types.h>
#include <linux/bvec.h>
#include <linux/device.h>
#if 0
#include <linux/ktime.h>
#endif

/*
 * The basic unit of block I/O is a sector. It is used in a number of contexts
 * in Linux (blk, bio, genhd). The size of one sector is 512 = 2**9
 * bytes. Variables of type sector_t represent an offset or size that is a
 * multiple of 512 bytes. Hence these two constants.
 */
#ifndef SECTOR_SHIFT
#define SECTOR_SHIFT 9
#endif
#ifndef SECTOR_SIZE
#define SECTOR_SIZE (1 << SECTOR_SHIFT)
#endif

struct bio_set;
struct bio;
struct bio_integrity_payload;
struct page;
struct io_context;
struct cgroup_subsys_state;
typedef void (bio_end_io_t) (struct bio *);
struct bio_crypt_ctx;

typedef u8 __bitwise blk_status_t;
typedef u16 blk_short_t;

/*
 * Operations and flags common to the bio and request structures.
 * We use 8 bits for encoding the operation, and the remaining 24 for flags.
 *
 * The least significant bit of the operation number indicates the data
 * transfer direction:
 *
 *   - if the least significant bit is set transfers are TO the device
 *   - if the least significant bit is not set transfers are FROM the device
 *
 * If a operation does not transfer data the least significant bit has no
 * meaning.
 */
#define REQ_OP_BITS     8
#define REQ_OP_MASK     ((1 << REQ_OP_BITS) - 1)
#define REQ_FLAG_BITS   24

struct block_device {
    sector_t        bd_start_sect;
    sector_t        bd_nr_sectors;
    //struct disk_stats __percpu *bd_stats;
    unsigned long       bd_stamp;
    bool            bd_read_only;   /* read-only policy */
    //dev_t           bd_dev;
    int         bd_openers;
#if 0
    struct inode *      bd_inode;   /* will die */
    struct super_block *    bd_super;
#endif
    void *          bd_claiming;
    struct device       bd_device;
    void *          bd_holder;
    int         bd_holders;
    bool            bd_write_holder;
    struct kobject      *bd_holder_dir;
    u8          bd_partno;
    spinlock_t      bd_size_lock; /* for bd_inode->i_size updates */
    struct gendisk *    bd_disk;
    struct request_queue *  bd_queue;

    /* The counter of freeze processes */
    int         bd_fsfreeze_count;
    /* Mutex for freeze */
    struct mutex        bd_fsfreeze_mutex;
#if 0
    struct super_block  *bd_fsfreeze_sb;

    struct partition_meta_info *bd_meta_info;
#endif
} __randomize_layout;

/*
 * main unit of I/O for the block layer and lower layers (ie drivers and
 * stacking drivers)
 */
struct bio {
    struct bio          *bi_next;   /* request queue link */
    struct block_device *bi_bdev;
    unsigned int        bi_opf;     /* bottom bits req flags,
                                     * top bits REQ_OP. Use
                                     * accessors.
                                     */
    unsigned short      bi_flags;   /* BIO_* below */
    unsigned short      bi_ioprio;
    blk_status_t        bi_status;
    atomic_t            __bi_remaining;

    struct bvec_iter    bi_iter;

#if 0
    blk_qc_t        bi_cookie;
    bio_end_io_t        *bi_end_io;
#endif
    void            *bi_private;

    unsigned short      bi_vcnt;    /* how many bio_vec's */

    /*
     * Everything starting with bi_max_vecs will be preserved by bio_reset()
     */

    unsigned short      bi_max_vecs;    /* max bvl_vecs we can hold */

    atomic_t        __bi_cnt;   /* pin count */

    struct bio_vec      *bi_io_vec; /* the actual vec list */

    struct bio_set      *bi_pool;

    /*
     * We can inline a number of vecs at the end of the bio, to avoid
     * double allocations for a small number of bio_vecs. This member
     * MUST obviously be kept at the very end of the bio.
     */
    struct bio_vec      bi_inline_vecs[];
};

enum req_opf {
    /* read sectors from the device */
    REQ_OP_READ     = 0,
    /* write sectors to the device */
    REQ_OP_WRITE        = 1,
    /* flush the volatile write cache */
    REQ_OP_FLUSH        = 2,
    /* discard sectors */
    REQ_OP_DISCARD      = 3,
    /* securely erase sectors */
    REQ_OP_SECURE_ERASE = 5,
    /* write the zero filled sector many times */
    REQ_OP_WRITE_ZEROES = 9,
    /* Open a zone */
    REQ_OP_ZONE_OPEN    = 10,
    /* Close a zone */
    REQ_OP_ZONE_CLOSE   = 11,
    /* Transition a zone to full */
    REQ_OP_ZONE_FINISH  = 12,
    /* write data at the current zone write pointer */
    REQ_OP_ZONE_APPEND  = 13,
    /* reset a zone write pointer */
    REQ_OP_ZONE_RESET   = 15,
    /* reset all the zone present on the device */
    REQ_OP_ZONE_RESET_ALL   = 17,

    /* Driver private requests */
    REQ_OP_DRV_IN       = 34,
    REQ_OP_DRV_OUT      = 35,

    REQ_OP_LAST,
};

#endif /* __LINUX_BLK_TYPES_H */

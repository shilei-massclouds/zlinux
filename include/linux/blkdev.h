/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Portions Copyright (C) 1992 Drew Eckhardt
 */
#ifndef _LINUX_BLKDEV_H
#define _LINUX_BLKDEV_H

#include <linux/types.h>
#include <linux/blk_types.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/llist.h>
#include <linux/minmax.h>
#if 0
#include <linux/timer.h>
#include <linux/workqueue.h>
#endif
#include <linux/wait.h>
#if 0
#include <linux/bio.h>
#endif
#include <linux/gfp.h>
#include <linux/kdev_t.h>
#include <linux/rcupdate.h>
#include <linux/percpu-refcount.h>
#if 0
#include <linux/blkzoned.h>
#endif
#include <linux/sched.h>
#include <linux/sbitmap.h>
#include <linux/srcu.h>
#if 0
#include <linux/uuid.h>
#endif
#include <linux/xarray.h>
#include <linux/bio.h>

/* Doing classic polling */
#define BLK_MQ_POLL_CLASSIC -1

#define DISK_MAX_PARTS  256
#define DISK_NAME_LEN   32
#define BDEVT_SIZE      10      /* Largest string for MAJ:MIN for blkdev */
#define BDEVNAME_SIZE   32      /* Largest string for a blockdev identifier */

#define BLKDEV_MAJOR_MAX    512

struct module;
struct request_queue;
struct elevator_queue;
struct blk_trace;
struct request;
struct sg_io_hdr;
struct blkcg_gq;
struct blk_flush_queue;
struct kiocb;
struct pr_ops;
struct rq_qos;
struct blk_queue_stats;
struct blk_stat_callback;
struct blk_crypto_profile;

struct blk_plug_cb;
typedef void (*blk_plug_cb_fn)(struct blk_plug_cb *, bool);
struct blk_plug_cb {
    struct list_head list;
    blk_plug_cb_fn callback;
    void *data;
};

extern const struct device_type disk_type;
extern struct device_type part_type;
extern struct class block_class;

#define PARTITION_META_INFO_VOLNAMELTH  64
/*
 * Enough for the string representation of any kind of UUID plus NULL.
 * EFI UUID is 36 characters. MSDOS UUID is 11 characters.
 */
#define PARTITION_META_INFO_UUIDLTH (UUID_STRING_LEN + 1)

struct partition_meta_info {
    char uuid[PARTITION_META_INFO_UUIDLTH];
    u8 volname[PARTITION_META_INFO_VOLNAMELTH];
};

struct gendisk {
    /*
     * major/first_minor/minors should not be set by any new driver, the
     * block core will take care of allocating them automatically.
     */
    int major;
    int first_minor;
    int minors;

    char disk_name[DISK_NAME_LEN];  /* name of major driver */

    unsigned short events;      /* supported events */
    unsigned short event_flags; /* flags related to event processing */

    struct xarray part_tbl;
    struct block_device *part0;

    const struct block_device_operations *fops;
    struct request_queue *queue;
    void *private_data;

    int flags;
    unsigned long state;
#define GD_NEED_PART_SCAN       0
#define GD_READ_ONLY            1
#define GD_DEAD                 2
#define GD_NATIVE_CAPACITY      3
#define GD_ADDED                4

    struct mutex open_mutex;    /* open/close mutex */
    unsigned open_partitions;   /* number of open partitions */

    struct backing_dev_info *bdi;
    struct kobject *slave_dir;
    struct timer_rand_state *random;
    atomic_t sync_io;       /* RAID */
    struct disk_events *ev;
#if 0
    struct cdrom_device_info *cdi;
#endif
    int node_id;
    struct badblocks *bb;
    struct lockdep_map lockdep_map;
    u64 diskseq;
};

/*
 * BLK_BOUNCE_NONE: never bounce (default)
 * BLK_BOUNCE_HIGH: bounce all highmem pages
 */
enum blk_bounce {
    BLK_BOUNCE_NONE,
    BLK_BOUNCE_HIGH,
};

enum blk_default_limits {
    BLK_MAX_SEGMENTS        = 128,
    BLK_SAFE_MAX_SECTORS    = 255,
    BLK_DEF_MAX_SECTORS     = 2560,
    BLK_MAX_SEGMENT_SIZE    = 65536,
    BLK_SEG_BOUNDARY_MASK   = 0xFFFFFFFFUL,
};

/*
 * Zoned block device models (zoned limit).
 *
 * Note: This needs to be ordered from the least to the most severe
 * restrictions for the inheritance in blk_stack_limits() to work.
 */
enum blk_zoned_model {
    BLK_ZONED_NONE = 0, /* Regular block device */
    BLK_ZONED_HA,       /* Host-aware zoned block device */
    BLK_ZONED_HM,       /* Host-managed zoned block device */
};

struct queue_limits {
    enum blk_bounce     bounce;
    unsigned long       seg_boundary_mask;
    unsigned long       virt_boundary_mask;

    unsigned int        max_hw_sectors;
    unsigned int        max_dev_sectors;
    unsigned int        chunk_sectors;
    unsigned int        max_sectors;
    unsigned int        max_segment_size;
    unsigned int        physical_block_size;
    unsigned int        logical_block_size;
    unsigned int        alignment_offset;
    unsigned int        io_min;
    unsigned int        io_opt;
    unsigned int        max_discard_sectors;
    unsigned int        max_hw_discard_sectors;
    unsigned int        max_write_zeroes_sectors;
    unsigned int        max_zone_append_sectors;
    unsigned int        discard_granularity;
    unsigned int        discard_alignment;
    unsigned int        zone_write_granularity;

    unsigned short      max_segments;
    unsigned short      max_integrity_segments;
    unsigned short      max_discard_segments;

    unsigned char       misaligned;
    unsigned char       discard_misaligned;
    unsigned char       raid_partial_stripes_expensive;
    enum blk_zoned_model    zoned;
};

struct request_queue {
    struct request      *last_merge;
    struct elevator_queue   *elevator;

    struct percpu_ref   q_usage_counter;

#if 0
    struct blk_queue_stats  *stats;
    struct rq_qos       *rq_qos;

#endif
    const struct blk_mq_ops *mq_ops;

    /* sw queues */
    struct blk_mq_ctx __percpu  *queue_ctx;

    unsigned int        queue_depth;

    /* hw dispatch queues */
    struct xarray       hctx_table;
    unsigned int        nr_hw_queues;

    /*
     * The queue owner gets to use this for whatever they like.
     * ll_rw_blk doesn't touch it.
     */
    void                *queuedata;

    /*
     * various queue flags, see QUEUE_* below
     */
    unsigned long       queue_flags;
    /*
     * Number of contexts that have called blk_set_pm_only(). If this
     * counter is above zero then only RQF_PM requests are processed.
     */
    atomic_t        pm_only;

    /*
     * ida allocated id for this queue.  Used to index queues from
     * ioctx.
     */
    int         id;

    spinlock_t      queue_lock;

    struct gendisk      *disk;

    /*
     * queue kobject
     */
    struct kobject kobj;

    /*
     * mq queue kobject
     */
    struct kobject *mq_kobj;

    struct device       *dev;
    enum rpm_status     rpm_status;

    /*
     * queue settings
     */
    unsigned long       nr_requests;    /* Max # of requests */

    unsigned int        dma_pad_mask;
    unsigned int        dma_alignment;

    unsigned int        rq_timeout;
    int         poll_nsec;

#if 0
    struct blk_stat_callback    *poll_cb;
    struct blk_rq_stat  *poll_stat;

    struct timer_list   timeout;
    struct work_struct  timeout_work;
#endif

    atomic_t        nr_active_requests_shared_tags;

    struct blk_mq_tags  *sched_shared_tags;

    struct list_head    icq_list;
    struct queue_limits limits;

    unsigned int        required_elevator_features;

    int                 node;
    struct mutex        debugfs_mutex;

    /*
     * for flush operations
     */
    struct blk_flush_queue  *fq;

    struct list_head    requeue_list;
    spinlock_t          requeue_lock;
    struct delayed_work requeue_work;

    struct mutex        sysfs_lock;
    struct mutex        sysfs_dir_lock;

    /*
     * for reusing dead hctx instance in case of updating
     * nr_hw_queues
     */
    struct list_head    unused_hctx_list;
    spinlock_t          unused_hctx_lock;

    int                 mq_freeze_depth;
    struct rcu_head     rcu_head;
    wait_queue_head_t   mq_freeze_wq;
    /*
     * Protect concurrent access to q_usage_counter by
     * percpu_ref_kill() and percpu_ref_reinit().
     */
    struct mutex        mq_freeze_lock;

    int                 quiesce_depth;

    struct blk_mq_tag_set   *tag_set;
    struct list_head    tag_set_list;
    struct bio_set      bio_split;
#if 0

    struct dentry       *debugfs_dir;

    struct dentry       *sched_debugfs_dir;
    struct dentry       *rqos_debugfs_dir;

    bool            mq_sysfs_init_done;

    /*
     * Independent sector access ranges. This is always NULL for
     * devices that do not have multiple independent access ranges.
     */
    struct blk_independent_access_ranges *ia_ranges;

#endif
    /**
     * @srcu: Sleepable RCU. Use as lock when type of the request queue
     * is blocking (BLK_MQ_F_BLOCKING). Must be the last member
     */
    struct srcu_struct  srcu[];
};

enum blk_unique_id {
    /* these match the Designator Types specified in SPC */
    BLK_UID_T10     = 1,
    BLK_UID_EUI64   = 2,
    BLK_UID_NAA     = 3,
};

/*
 * blk_plug permits building a queue of related requests by holding the I/O
 * fragments for a short period. This allows merging of sequential requests
 * into single larger request. As the requests are moved from a per-task list to
 * the device's request_queue in a batch, this results in improved scalability
 * as the lock contention for request_queue lock is reduced.
 *
 * It is ok not to disable preemption when adding the request to the plug list
 * or when attempting a merge. For details, please see schedule() where
 * blk_flush_plug() is called.
 */
struct blk_plug {
    struct request *mq_list; /* blk-mq requests */

    /* if ios_left is > 1, we can batch tag/rq allocations */
    struct request *cached_rq;
    unsigned short nr_ios;

    unsigned short rq_count;

    bool multiple_queues;
    bool has_elevator;
    bool nowait;

    struct list_head cb_list; /* md requires an unplug callback */
};

/**
 * DOC: genhd capability flags
 *
 * ``GENHD_FL_REMOVABLE``: indicates that the block device gives access to
 * removable media.  When set, the device remains present even when media is not
 * inserted.  Shall not be set for devices which are removed entirely when the
 * media is removed.
 *
 * ``GENHD_FL_HIDDEN``: the block device is hidden; it doesn't produce events,
 * doesn't appear in sysfs, and can't be opened from userspace or using
 * blkdev_get*. Used for the underlying components of multipath devices.
 *
 * ``GENHD_FL_NO_PART``: partition support is disabled.  The kernel will not
 * scan for partitions from add_disk, and users can't add partitions manually.
 *
 */
enum {
    GENHD_FL_REMOVABLE  = 1 << 0,
    GENHD_FL_HIDDEN     = 1 << 1,
    GENHD_FL_NO_PART    = 1 << 2,
};

enum {
    /* Poll even if events_poll_msecs is unset */
    DISK_EVENT_FLAG_POLL            = 1 << 0,
    /* Forward events to udev */
    DISK_EVENT_FLAG_UEVENT          = 1 << 1,
    /* Block event polling when open for exclusive write */
    DISK_EVENT_FLAG_BLOCK_ON_EXCL_WRITE = 1 << 2,
};

struct block_device_operations {
    void (*submit_bio)(struct bio *bio);
    int (*poll_bio)(struct bio *bio, struct io_comp_batch *iob,
                    unsigned int flags);
    int (*open) (struct block_device *, fmode_t);
    void (*release) (struct gendisk *, fmode_t);
    int (*rw_page)(struct block_device *, sector_t, struct page *,
                   unsigned int);
    int (*ioctl) (struct block_device *, fmode_t, unsigned, unsigned long);
    int (*compat_ioctl) (struct block_device *, fmode_t, unsigned,
                         unsigned long);
    unsigned int (*check_events) (struct gendisk *disk, unsigned int clearing);
    void (*unlock_native_capacity) (struct gendisk *);
    int (*getgeo)(struct block_device *, struct hd_geometry *);
    int (*set_read_only)(struct block_device *bdev, bool ro);
    void (*free_disk)(struct gendisk *disk);
    /* this callback is with swap_lock and sometimes page table lock held */
    void (*swap_slot_free_notify) (struct block_device *, unsigned long);
#if 0
    int (*report_zones)(struct gendisk *, sector_t sector,
                        unsigned int nr_zones, report_zones_cb cb, void *data);
#endif
    char *(*devnode)(struct gendisk *disk, umode_t *mode);
    /* returns the length of the identifier or a negative errno: */
    int (*get_unique_id)(struct gendisk *disk, u8 id[16],
                         enum blk_unique_id id_type);
    struct module *owner;
#if 0
    const struct pr_ops *pr_ops;
#endif

    /*
     * Special callback for probing GPT entry at a given sector.
     * Needed by Android devices, used by GPT scanner and MMC blk
     * driver.
     */
    int (*alternative_gpt_sector)(struct gendisk *disk, sector_t *sector);
};

extern void blk_cleanup_queue(struct request_queue *);

struct gendisk *__alloc_disk_node(struct request_queue *q, int node_id,
                                  struct lock_class_key *lkclass);
void put_disk(struct gendisk *disk);
struct gendisk *__blk_alloc_disk(int node, struct lock_class_key *lkclass);

/* Keep blk_queue_flag_name[] in sync with the definitions below */
#define QUEUE_FLAG_STOPPED      0   /* queue is stopped */
#define QUEUE_FLAG_DYING        1   /* queue being torn down */
#define QUEUE_FLAG_HAS_SRCU     2   /* SRCU is allocated */
#define QUEUE_FLAG_NOMERGES     3   /* disable merge attempts */
#define QUEUE_FLAG_SAME_COMP    4   /* complete on same CPU-group */
#define QUEUE_FLAG_FAIL_IO      5   /* fake timeout */
#define QUEUE_FLAG_NONROT       6   /* non-rotational device (SSD) */
#define QUEUE_FLAG_VIRT QUEUE_FLAG_NONROT /* paravirt device */
#define QUEUE_FLAG_IO_STAT      7   /* do disk/partitions IO accounting */
#define QUEUE_FLAG_DISCARD      8   /* supports DISCARD */
#define QUEUE_FLAG_NOXMERGES    9   /* No extended merges */
#define QUEUE_FLAG_ADD_RANDOM   10  /* Contributes to random pool */
#define QUEUE_FLAG_SECERASE     11  /* supports secure erase */
#define QUEUE_FLAG_SAME_FORCE   12  /* force complete on same CPU */
#define QUEUE_FLAG_DEAD         13  /* queue tear-down finished */
#define QUEUE_FLAG_INIT_DONE    14  /* queue is initialized */
#define QUEUE_FLAG_STABLE_WRITES 15 /* don't modify blks until WB is done */
#define QUEUE_FLAG_POLL     16  /* IO polling enabled if set */
#define QUEUE_FLAG_WC       17  /* Write back caching */
#define QUEUE_FLAG_FUA      18  /* device supports FUA writes */
#define QUEUE_FLAG_DAX      19  /* device supports DAX */
#define QUEUE_FLAG_STATS    20  /* track IO start and completion times */
#define QUEUE_FLAG_REGISTERED   22  /* queue has been registered to a disk */
#define QUEUE_FLAG_QUIESCED 24  /* queue has been quiesced */
#define QUEUE_FLAG_PCI_P2PDMA   25  /* device supports PCI p2p requests */
#define QUEUE_FLAG_ZONE_RESETALL 26 /* supports Zone Reset All */
#define QUEUE_FLAG_RQ_ALLOC_TIME 27 /* record rq->alloc_time_ns */
#define QUEUE_FLAG_HCTX_ACTIVE  28  /* at least one blk-mq hctx is active */
#define QUEUE_FLAG_NOWAIT       29  /* device supports NOWAIT */

#define QUEUE_FLAG_MQ_DEFAULT \
    ((1 << QUEUE_FLAG_IO_STAT) | \
     (1 << QUEUE_FLAG_SAME_COMP) | \
     (1 << QUEUE_FLAG_NOWAIT))

#define blk_queue_dying(q)      test_bit(QUEUE_FLAG_DYING, &(q)->queue_flags)
#define blk_queue_has_srcu(q)   test_bit(QUEUE_FLAG_HAS_SRCU, &(q)->queue_flags)
#define blk_queue_nowait(q)     test_bit(QUEUE_FLAG_NOWAIT, &(q)->queue_flags)
#define blk_queue_discard(q)    test_bit(QUEUE_FLAG_DISCARD, &(q)->queue_flags)
#define blk_queue_nomerges(q)   test_bit(QUEUE_FLAG_NOMERGES, &(q)->queue_flags)

#define blk_queue_stable_writes(q) \
    test_bit(QUEUE_FLAG_STABLE_WRITES, &(q)->queue_flags)

#define blk_queue_io_stat(q)    test_bit(QUEUE_FLAG_IO_STAT, &(q)->queue_flags)
#define blk_queue_quiesced(q) \
    test_bit(QUEUE_FLAG_QUIESCED, &(q)->queue_flags)

#define blk_queue_secure_erase(q) \
    (test_bit(QUEUE_FLAG_SECERASE, &(q)->queue_flags))
#define blk_queue_zone_resetall(q)  \
    test_bit(QUEUE_FLAG_ZONE_RESETALL, &(q)->queue_flags)

#define blk_queue_pm_only(q)    atomic_read(&(q)->pm_only)
#define blk_queue_registered(q) \
    test_bit(QUEUE_FLAG_REGISTERED, &(q)->queue_flags)

bool __must_check blk_get_queue(struct request_queue *);
extern void blk_put_queue(struct request_queue *);

void blk_queue_flag_set(unsigned int flag, struct request_queue *q);
void blk_queue_flag_clear(unsigned int flag, struct request_queue *q);
bool blk_queue_flag_test_and_set(unsigned int flag, struct request_queue *q);

extern void blk_queue_write_cache(struct request_queue *q,
                                  bool enabled,
                                  bool fua);

void set_disk_ro(struct gendisk *disk, bool read_only);

extern void blk_queue_max_segments(struct request_queue *, unsigned short);

extern void blk_queue_max_hw_sectors(struct request_queue *, unsigned int);

extern void blk_queue_max_segment_size(struct request_queue *, unsigned int);

extern void blk_queue_logical_block_size(struct request_queue *, unsigned int);

extern void blk_queue_physical_block_size(struct request_queue *, unsigned int);

extern void blk_queue_alignment_offset(struct request_queue *q,
                                       unsigned int alignment);

extern void blk_queue_io_opt(struct request_queue *q, unsigned int opt);

extern void blk_queue_io_min(struct request_queue *q, unsigned int min);

extern void blk_queue_max_discard_sectors(struct request_queue *q,
                                          unsigned int max_discard_sectors);

extern void blk_queue_max_discard_segments(struct request_queue *,
                                           unsigned short);

extern void
blk_queue_max_write_zeroes_sectors(struct request_queue *q,
                                   unsigned int max_write_same_sectors);

static inline int blk_validate_block_size(unsigned long bsize)
{
    if (bsize < 512 || bsize > PAGE_SIZE || !is_power_of_2(bsize))
        return -EINVAL;

    return 0;
}

static inline unsigned queue_logical_block_size(const struct request_queue *q)
{
    int retval = 512;

    if (q && q->limits.logical_block_size)
        retval = q->limits.logical_block_size;

    return retval;
}

static inline unsigned int queue_io_opt(const struct request_queue *q)
{
    return q->limits.io_opt;
}

static inline sector_t bdev_nr_sectors(struct block_device *bdev)
{
    return bdev->bd_nr_sectors;
}

static inline sector_t get_capacity(struct gendisk *disk)
{
    return bdev_nr_sectors(disk->part0);
}

bool set_capacity_and_notify(struct gendisk *disk, sector_t size);

struct block_device *bdev_alloc(struct gendisk *disk, u8 partno);

int __must_check device_add_disk(struct device *parent, struct gendisk *disk,
                                 const struct attribute_group **groups);

static inline bool disk_live(struct gendisk *disk)
{
    return !inode_unhashed(disk->part0->bd_inode);
}

/*
 * The gendisk is refcounted by the part0 block_device, and the bd_device
 * therein is also used for device model presentation in sysfs.
 */
#define dev_to_disk(device) \
    (dev_to_bdev(device)->bd_disk)
#define disk_to_dev(disk) \
    (&((disk)->part0->bd_device))

static inline bool queue_is_mq(struct request_queue *q)
{
    return q->mq_ops;
}

int __register_blkdev(unsigned int major, const char *name,
                      void (*probe)(dev_t devt));
#define register_blkdev(major, name) \
    __register_blkdev(major, name, NULL)

int iocb_bio_iopoll(struct kiocb *kiocb, struct io_comp_batch *iob,
                    unsigned int flags);

void invalidate_bdev(struct block_device *bdev);
int sync_blockdev(struct block_device *bdev);
int sync_blockdev_nowait(struct block_device *bdev);
void sync_bdevs(bool wait);
void printk_all_partitions(void);

static inline bool bdev_is_partition(struct block_device *bdev)
{
    return bdev->bd_partno;
}

struct block_device *
blkdev_get_by_path(const char *path, fmode_t mode, void *holder);
struct block_device *blkdev_get_by_dev(dev_t dev, fmode_t mode, void *holder);
int bd_prepare_to_claim(struct block_device *bdev, void *holder);
void bd_abort_claiming(struct block_device *bdev, void *holder);
void blkdev_put(struct block_device *bdev, fmode_t mode);

dev_t part_devt(struct gendisk *disk, u8 partno);
void inc_diskseq(struct gendisk *disk);
dev_t blk_lookup_devt(const char *name, int partno);
void blk_request_module(dev_t devt);

static inline int get_disk_ro(struct gendisk *disk)
{
    return disk->part0->bd_read_only || test_bit(GD_READ_ONLY, &disk->state);
}

static inline int bdev_read_only(struct block_device *bdev)
{
    return bdev->bd_read_only || get_disk_ro(bdev->bd_disk);
}

void bdev_add(struct block_device *bdev, dev_t dev);
struct block_device *I_BDEV(struct inode *inode);
int truncate_bdev_range(struct block_device *bdev, fmode_t mode, loff_t lstart,
                        loff_t lend);

static inline dev_t disk_devt(struct gendisk *disk)
{
    return MKDEV(disk->major, disk->first_minor);
}

static inline struct request_queue *bdev_get_queue(struct block_device *bdev)
{
    return bdev->bd_queue;  /* this is never NULL */
}

static inline unsigned int bdev_logical_block_size(struct block_device *bdev)
{
    return queue_logical_block_size(bdev_get_queue(bdev));
}

/* assumes size > 256 */
static inline unsigned int blksize_bits(unsigned int size)
{
    unsigned int bits = 8;
    do {
        bits++;
        size >>= 1;
    } while (size > 256);
    return bits;
}

int bdev_disk_changed(struct gendisk *disk, bool invalidate);

void set_capacity(struct gendisk *disk, sector_t size);

static inline loff_t bdev_nr_bytes(struct block_device *bdev)
{
    return (loff_t)bdev_nr_sectors(bdev) << SECTOR_SHIFT;
}

void submit_bio_noacct(struct bio *bio);

static inline enum blk_zoned_model
blk_queue_zoned_model(struct request_queue *q)
{
    return BLK_ZONED_NONE;
}

static inline bool blk_queue_is_zoned(struct request_queue *q)
{
    switch (blk_queue_zoned_model(q)) {
    case BLK_ZONED_HA:
    case BLK_ZONED_HM:
        return true;
    default:
        return false;
    }
}

extern int blk_lld_busy(struct request_queue *q);
extern void blk_queue_split(struct bio **);
extern int blk_queue_enter(struct request_queue *q, blk_mq_req_flags_t flags);
extern void blk_queue_exit(struct request_queue *q);
extern void blk_sync_queue(struct request_queue *q);

static inline enum rpm_status queue_rpm_status(struct request_queue *q)
{
    return q->rpm_status;
}

static inline bool blk_op_is_passthrough(unsigned int op)
{
    op &= REQ_OP_MASK;
    return op == REQ_OP_DRV_IN || op == REQ_OP_DRV_OUT;
}

static inline unsigned int queue_max_segment_size(const struct request_queue *q)
{
    return q->limits.max_segment_size;
}

static inline unsigned long
queue_segment_boundary(const struct request_queue *q)
{
    return q->limits.seg_boundary_mask;
}

/* This should not be used directly - use rq_for_each_segment */
#define for_each_bio(_bio)      \
    for (; _bio; _bio = _bio->bi_next)

void __blk_flush_plug(struct blk_plug *plug, bool from_schedule);
static inline void blk_flush_plug(struct blk_plug *plug, bool async)
{
    if (plug)
        __blk_flush_plug(plug, async);
}

extern const char *blk_op_str(unsigned int op);

static inline unsigned int block_size(struct block_device *bdev)
{
    return 1 << bdev->bd_inode->i_blkbits;
}

struct block_device *I_BDEV(struct inode *inode);

extern int bdev_read_page(struct block_device *, sector_t, struct page *);

int blk_status_to_errno(blk_status_t status);

/*
 * Return maximum size of a request at given offset. Only valid for
 * file system requests.
 */
static inline unsigned int blk_max_size_offset(struct request_queue *q,
                                               sector_t offset,
                                               unsigned int chunk_sectors)
{
    if (!chunk_sectors) {
        if (q->limits.chunk_sectors)
            chunk_sectors = q->limits.chunk_sectors;
        else
            return q->limits.max_sectors;
    }

    if (likely(is_power_of_2(chunk_sectors)))
        chunk_sectors -= offset & (chunk_sectors - 1);
    else
        chunk_sectors -= sector_div(offset, chunk_sectors);

    return min(q->limits.max_sectors, chunk_sectors);
}

static inline unsigned int
queue_physical_block_size(const struct request_queue *q)
{
    return q->limits.physical_block_size;
}

static inline unsigned int bdev_physical_block_size(struct block_device *bdev)
{
    return queue_physical_block_size(bdev_get_queue(bdev));
}

extern void blk_queue_max_segments(struct request_queue *, unsigned short);

static inline unsigned short queue_max_segments(const struct request_queue *q)
{
    return q->limits.max_segments;
}

static inline unsigned long queue_virt_boundary(const struct request_queue *q)
{
    return q->limits.virt_boundary_mask;
}

extern void blk_set_default_limits(struct queue_limits *lim);
extern void blk_set_stacking_limits(struct queue_limits *lim);

extern void blk_start_plug(struct blk_plug *);
extern void blk_start_plug_nr_ios(struct blk_plug *, unsigned short);
extern void blk_finish_plug(struct blk_plug *);

static inline
unsigned short queue_max_discard_segments(const struct request_queue *q)
{
    return q->limits.max_discard_segments;
}

int kblockd_mod_delayed_work_on(int cpu, struct delayed_work *dwork,
                                unsigned long delay);

#endif /* _LINUX_BLKDEV_H */

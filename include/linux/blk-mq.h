/* SPDX-License-Identifier: GPL-2.0 */
#ifndef BLK_MQ_H
#define BLK_MQ_H

#include <linux/blkdev.h>
#include <linux/sbitmap.h>
#include <linux/scatterlist.h>
#include <linux/prefetch.h>
#include <linux/llist.h>
#include <linux/bvec.h>

#define BLK_MQ_NO_HCTX_IDX  (-1U)

#define BLK_TAG_ALLOC_FIFO  0 /* allocate starting from 0 */
#define BLK_TAG_ALLOC_RR    1 /* allocate starting from last allocated tag */

struct blk_mq_tags;
struct blk_flush_queue;

typedef void (rq_end_io_fn)(struct request *, blk_status_t);

/*
 * request flags */
typedef __u32 __bitwise req_flags_t;

/**
 * struct blk_mq_queue_map - Map software queues to hardware queues
 * @mq_map:       CPU ID to hardware queue index map. This is an array
 *  with nr_cpu_ids elements. Each element has a value in the range
 *  [@queue_offset, @queue_offset + @nr_queues).
 * @nr_queues:    Number of hardware queues to map CPU IDs onto.
 * @queue_offset: First hardware queue to map onto. Used by the PCIe NVMe
 *  driver to map each hardware queue type (enum hctx_type) onto a distinct
 *  set of hardware queues.
 */
struct blk_mq_queue_map {
    unsigned int *mq_map;
    unsigned int nr_queues;
    unsigned int queue_offset;
};

enum mq_rq_state {
    MQ_RQ_IDLE          = 0,
    MQ_RQ_IN_FLIGHT     = 1,
    MQ_RQ_COMPLETE      = 2,
};

enum {
    BLK_MQ_F_SHOULD_MERGE       = 1 << 0,
    BLK_MQ_F_TAG_QUEUE_SHARED   = 1 << 1,
    /*
     * Set when this device requires underlying blk-mq device for
     * completing IO:
     */
    BLK_MQ_F_STACKING           = 1 << 2,
    BLK_MQ_F_TAG_HCTX_SHARED    = 1 << 3,
    BLK_MQ_F_BLOCKING           = 1 << 5,
    /* Do not allow an I/O scheduler to be configured. */
    BLK_MQ_F_NO_SCHED           = 1 << 6,
    /*
     * Select 'none' during queue registration in case of a single hwq
     * or shared hwqs instead of 'mq-deadline'.
     */
    BLK_MQ_F_NO_SCHED_BY_DEFAULT    = 1 << 7,
    BLK_MQ_F_ALLOC_POLICY_START_BIT = 8,
    BLK_MQ_F_ALLOC_POLICY_BITS      = 1,

    BLK_MQ_S_STOPPED        = 0,
    BLK_MQ_S_TAG_ACTIVE     = 1,
    BLK_MQ_S_SCHED_RESTART  = 2,

    /* hw queue is inactive after all its CPUs become offline */
    BLK_MQ_S_INACTIVE       = 3,

    BLK_MQ_MAX_DEPTH        = 10240,

    BLK_MQ_CPU_WORK_BATCH   = 8,
};
#define BLK_MQ_FLAG_TO_ALLOC_POLICY(flags) \
    ((flags >> BLK_MQ_F_ALLOC_POLICY_START_BIT) & \
     ((1 << BLK_MQ_F_ALLOC_POLICY_BITS) - 1))

/*
 * Try to put the fields that are referenced together in the same cacheline.
 *
 * If you modify this structure, make sure to update blk_rq_init() and
 * especially blk_mq_rq_ctx_init() to take care of the added fields.
 */
struct request {
    struct request_queue *q;
    struct blk_mq_ctx *mq_ctx;
    struct blk_mq_hw_ctx *mq_hctx;

    unsigned int cmd_flags;     /* op and common flags */
    req_flags_t rq_flags;

    int tag;
    int internal_tag;

    unsigned int timeout;

    /* the following two fields are internal, NEVER access directly */
    unsigned int __data_len;    /* total data len */
    sector_t __sector;      /* sector cursor */

    struct bio *bio;
    struct bio *biotail;

    union {
        struct list_head queuelist;
        struct request *rq_next;
    };

    struct block_device *part;

    /* Time that this request was allocated for this IO. */
    u64 start_time_ns;
    /* Time that I/O was submitted to the device. */
    u64 io_start_time_ns;

    /*
     * rq sectors used for blk stats. It has the same value
     * with blk_rq_sectors(rq), except that it never be zeroed
     * by completion.
     */
    unsigned short stats_sectors;

    /*
     * Number of scatter-gather DMA addr+len pairs after
     * physical address coalescing is performed.
     */
    unsigned short nr_phys_segments;

    unsigned short write_hint;
    unsigned short ioprio;

    enum mq_rq_state state;
    atomic_t ref;

    unsigned long deadline;

    /*
     * The hash is used inside the scheduler, and killed once the
     * request reaches the dispatch list. The ipi_list is only used
     * to queue the request for softirq completion, which is long
     * after the request has been unhashed (and even removed from
     * the dispatch list).
     */
    union {
        struct hlist_node hash; /* merge hash */
        struct llist_node ipi_list;
    };

    /*
     * The rb_node is only used inside the io scheduler, requests
     * are pruned when moved to the dispatch queue. So let the
     * completion_data share space with the rb_node.
     */
    union {
        struct rb_node rb_node; /* sort/lookup */
        struct bio_vec special_vec;
        void *completion_data;
    };

    /*
     * Three pointers are available for the IO schedulers, if they need
     * more they have to dynamically allocate it.  Flush requests are
     * never put on the IO scheduler. So let the flush fields share
     * space with the elevator data.
     */
    union {
        struct {
            struct io_cq        *icq;
            void            *priv[2];
        } elv;

        struct {
            unsigned int        seq;
            struct list_head    list;
            rq_end_io_fn        *saved_end_io;
        } flush;
    };

    union {
        struct __call_single_data csd;
        u64 fifo_time;
    };

    /*
     * completion callback.
     */
    rq_end_io_fn *end_io;
    void *end_io_data;
};

/**
 * struct blk_mq_queue_data - Data about a request inserted in a queue
 *
 * @rq:   Request pointer.
 * @last: If it is the last request in the queue.
 */
struct blk_mq_queue_data {
    struct request *rq;
    bool last;
};


/**
 * enum hctx_type - Type of hardware queue
 * @HCTX_TYPE_DEFAULT:  All I/O not otherwise accounted for.
 * @HCTX_TYPE_READ: Just for READ I/O.
 * @HCTX_TYPE_POLL: Polled I/O of any kind.
 * @HCTX_MAX_TYPES: Number of types of hctx.
 */
enum hctx_type {
    HCTX_TYPE_DEFAULT,
    HCTX_TYPE_READ,
    HCTX_TYPE_POLL,

    HCTX_MAX_TYPES,
};

/**
 * struct blk_mq_tag_set - tag set that can be shared between request queues
 * @map:       One or more ctx -> hctx mappings. One map exists for each
 *         hardware queue type (enum hctx_type) that the driver wishes
 *         to support. There are no restrictions on maps being of the
 *         same size, and it's perfectly legal to share maps between
 *         types.
 * @nr_maps:       Number of elements in the @map array. A number in the range
 *         [1, HCTX_MAX_TYPES].
 * @ops:       Pointers to functions that implement block driver behavior.
 * @nr_hw_queues:  Number of hardware queues supported by the block driver that
 *         owns this data structure.
 * @queue_depth:   Number of tags per hardware queue, reserved tags included.
 * @reserved_tags: Number of tags to set aside for BLK_MQ_REQ_RESERVED tag
 *         allocations.
 * @cmd_size:      Number of additional bytes to allocate per request. The block
 *         driver owns these additional bytes.
 * @numa_node:     NUMA node the storage adapter has been connected to.
 * @timeout:       Request processing timeout in jiffies.
 * @flags:     Zero or more BLK_MQ_F_* flags.
 * @driver_data:   Pointer to data owned by the block driver that created this
 *         tag set.
 * @tags:      Tag sets. One tag set per hardware queue. Has @nr_hw_queues
 *         elements.
 * @shared_tags:
 *         Shared set of tags. Has @nr_hw_queues elements. If set,
 *         shared by all @tags.
 * @tag_list_lock: Serializes tag_list accesses.
 * @tag_list:      List of the request queues that use this tag set. See also
 *         request_queue.tag_set_list.
 */
struct blk_mq_tag_set {
    struct blk_mq_queue_map map[HCTX_MAX_TYPES];
    unsigned int        nr_maps;
    const struct        blk_mq_ops *ops;
    unsigned int        nr_hw_queues;
    unsigned int        queue_depth;
    unsigned int        reserved_tags;
    unsigned int        cmd_size;
    int                 numa_node;
    unsigned int        timeout;
    unsigned int        flags;
    void                *driver_data;

    struct blk_mq_tags  **tags;

    struct blk_mq_tags  *shared_tags;

    struct mutex        tag_list_lock;
    struct list_head    tag_list;
};

/**
 * struct blk_mq_ops - Callback functions that implements block driver
 * behaviour.
 */
struct blk_mq_ops {
    /**
     * @queue_rq: Queue a new request from block IO.
     */
    blk_status_t (*queue_rq)(struct blk_mq_hw_ctx *,
                             const struct blk_mq_queue_data *);

    /**
     * @commit_rqs: If a driver uses bd->last to judge when to submit
     * requests to hardware, it must define this function. In case of errors
     * that make us stop issuing further requests, this hook serves the
     * purpose of kicking the hardware (which the last request otherwise
     * would have done).
     */
    void (*commit_rqs)(struct blk_mq_hw_ctx *);

    /**
     * @queue_rqs: Queue a list of new requests. Driver is guaranteed
     * that each request belongs to the same queue. If the driver doesn't
     * empty the @rqlist completely, then the rest will be queued
     * individually by the block layer upon return.
     */
    void (*queue_rqs)(struct request **rqlist);

    /**
     * @get_budget: Reserve budget before queue request, once .queue_rq is
     * run, it is driver's responsibility to release the
     * reserved budget. Also we have to handle failure case
     * of .get_budget for avoiding I/O deadlock.
     */
    int (*get_budget)(struct request_queue *);

    /**
     * @put_budget: Release the reserved budget.
     */
    void (*put_budget)(struct request_queue *, int);

    /**
     * @set_rq_budget_token: store rq's budget token
     */
    void (*set_rq_budget_token)(struct request *, int);

    /**
     * @get_rq_budget_token: retrieve rq's budget token
     */
    int (*get_rq_budget_token)(struct request *);

    /**
     * @timeout: Called on request timeout.
     */
    enum blk_eh_timer_return (*timeout)(struct request *, bool);

    /**
     * @poll: Called to poll for completion of a specific tag.
     */
    int (*poll)(struct blk_mq_hw_ctx *, struct io_comp_batch *);

    /**
     * @complete: Mark the request as complete.
     */
    void (*complete)(struct request *);

    /**
     * @init_hctx: Called when the block layer side of a hardware queue has
     * been set up, allowing the driver to allocate/init matching
     * structures.
     */
    int (*init_hctx)(struct blk_mq_hw_ctx *, void *, unsigned int);

    /**
     * @exit_hctx: Ditto for exit/teardown.
     */
    void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);

    /**
     * @init_request: Called for every command allocated by the block layer
     * to allow the driver to set up driver specific data.
     *
     * Tag greater than or equal to queue_depth is for setting up
     * flush request.
     */
    int (*init_request)(struct blk_mq_tag_set *set, struct request *,
                        unsigned int, unsigned int);
    /**
     * @exit_request: Ditto for exit/teardown.
     */
    void (*exit_request)(struct blk_mq_tag_set *set, struct request *,
                         unsigned int);

    /**
     * @cleanup_rq: Called before freeing one request which isn't completed
     * yet, and usually for freeing the driver private data.
     */
    void (*cleanup_rq)(struct request *);

    /**
     * @busy: If set, returns whether or not this queue currently is busy.
     */
    bool (*busy)(struct request_queue *);

    /**
     * @map_queues: This allows drivers specify their own queue mapping by
     * overriding the setup-time function that builds the mq_map.
     */
    int (*map_queues)(struct blk_mq_tag_set *set);
};

enum {
    BLK_MQ_UNIQUE_TAG_BITS = 16,
    BLK_MQ_UNIQUE_TAG_MASK = (1 << BLK_MQ_UNIQUE_TAG_BITS) - 1,
};

/*
 * Tag address space map.
 */
struct blk_mq_tags {
    unsigned int nr_tags;
    unsigned int nr_reserved_tags;

    atomic_t active_queues;

    struct sbitmap_queue bitmap_tags;
    struct sbitmap_queue breserved_tags;

    struct request **rqs;
    struct request **static_rqs;
    struct list_head page_list;

    /*
     * used to clear request reference in rqs[] before freeing one
     * request pool
     */
    spinlock_t lock;
};

int blk_mq_alloc_tag_set(struct blk_mq_tag_set *set);

int blk_mq_map_queues(struct blk_mq_queue_map *qmap);

#endif /* BLK_MQ_H */

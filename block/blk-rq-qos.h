/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RQ_QOS_H
#define RQ_QOS_H

#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/blk_types.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/blk-mq.h>

//#include "blk-mq-debugfs.h"

struct blk_mq_debugfs_attr;

enum rq_qos_id {
    RQ_QOS_WBT,
    RQ_QOS_LATENCY,
    RQ_QOS_COST,
    RQ_QOS_IOPRIO,
};

struct rq_qos {
    struct rq_qos_ops *ops;
    struct request_queue *q;
    enum rq_qos_id id;
    struct rq_qos *next;
#if 0
    struct dentry *debugfs_dir;
#endif
};

struct rq_qos_ops {
    void (*throttle)(struct rq_qos *, struct bio *);
    void (*track)(struct rq_qos *, struct request *, struct bio *);
    void (*merge)(struct rq_qos *, struct request *, struct bio *);
    void (*issue)(struct rq_qos *, struct request *);
    void (*requeue)(struct rq_qos *, struct request *);
    void (*done)(struct rq_qos *, struct request *);
    void (*done_bio)(struct rq_qos *, struct bio *);
    void (*cleanup)(struct rq_qos *, struct bio *);
    void (*queue_depth_changed)(struct rq_qos *);
    void (*exit)(struct rq_qos *);
    const struct blk_mq_debugfs_attr *debugfs_attrs;
};

void __rq_qos_merge(struct rq_qos *rqos, struct request *rq,
                    struct bio *bio);

static inline
void rq_qos_merge(struct request_queue *q, struct request *rq,
                  struct bio *bio)
{
    if (q->rq_qos) {
        bio_set_flag(bio, BIO_QOS_MERGED);
        __rq_qos_merge(q->rq_qos, rq, bio);
    }
}

#endif /* RQ_QOS_H */

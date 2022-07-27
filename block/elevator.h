/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ELEVATOR_H
#define _ELEVATOR_H

#include <linux/percpu.h>
#include <linux/hashtable.h>

struct blk_mq_alloc_data;
struct blk_mq_hw_ctx;

struct elevator_mq_ops {
    int (*init_sched)(struct request_queue *, struct elevator_type *);
    void (*exit_sched)(struct elevator_queue *);
    int (*init_hctx)(struct blk_mq_hw_ctx *, unsigned int);
    void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);
    void (*depth_updated)(struct blk_mq_hw_ctx *);

    bool (*allow_merge)(struct request_queue *, struct request *, struct bio *);
    bool (*bio_merge)(struct request_queue *, struct bio *, unsigned int);
    int (*request_merge)(struct request_queue *q, struct request **, struct bio *);
    void (*request_merged)(struct request_queue *, struct request *, enum elv_merge);
    void (*requests_merged)(struct request_queue *, struct request *, struct request *);
    void (*limit_depth)(unsigned int, struct blk_mq_alloc_data *);
    void (*prepare_request)(struct request *);
    void (*finish_request)(struct request *);
    void (*insert_requests)(struct blk_mq_hw_ctx *, struct list_head *, bool);
    struct request *(*dispatch_request)(struct blk_mq_hw_ctx *);
    bool (*has_work)(struct blk_mq_hw_ctx *);
    void (*completed_request)(struct request *, u64);
    void (*requeue_request)(struct request *);
    struct request *(*former_request)(struct request_queue *, struct request *);
    struct request *(*next_request)(struct request_queue *, struct request *);
    void (*init_icq)(struct io_cq *);
    void (*exit_icq)(struct io_cq *);
};

#define ELV_NAME_MAX    (16)

/*
 * identifies an elevator type, such as AS or deadline
 */
struct elevator_type
{
    /* managed by elevator core */
    struct kmem_cache *icq_cache;

    /* fields provided by elevator implementation */
    struct elevator_mq_ops ops;

    size_t icq_size;    /* see iocontext.h */
    size_t icq_align;   /* ditto */
    struct elv_fs_entry *elevator_attrs;
    const char *elevator_name;
    const char *elevator_alias;
    const unsigned int elevator_features;
    struct module *elevator_owner;
#if 0
    const struct blk_mq_debugfs_attr *queue_debugfs_attrs;
    const struct blk_mq_debugfs_attr *hctx_debugfs_attrs;
#endif

    /* managed by elevator core */
    char icq_cache_name[ELV_NAME_MAX + 6];  /* elvname + "_io_cq" */
    struct list_head list;
};

#define ELV_HASH_BITS 6

/*
 * each queue has an elevator_queue associated with it
 */
struct elevator_queue
{
    struct elevator_type *type;
    void *elevator_data;
    struct kobject kobj;
    struct mutex sysfs_lock;
    unsigned int registered:1;
    DECLARE_HASHTABLE(hash, ELV_HASH_BITS);
};

void elevator_init_mq(struct request_queue *q);

/*
 * io scheduler registration
 */
extern int elv_register(struct elevator_type *);
extern void elv_unregister(struct elevator_type *);

#endif /* _ELEVATOR_H */

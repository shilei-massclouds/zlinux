// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/slab.h>
//#include <linux/workqueue.h>
#include <linux/smp.h>

#include <linux/blk-mq.h>
#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-tag.h"

static void blk_mq_sysfs_release(struct kobject *kobj)
{
    struct blk_mq_ctxs *ctxs = container_of(kobj, struct blk_mq_ctxs, kobj);

    free_percpu(ctxs->queue_ctx);
    kfree(ctxs);
}

static void blk_mq_ctx_sysfs_release(struct kobject *kobj)
{
    struct blk_mq_ctx *ctx = container_of(kobj, struct blk_mq_ctx, kobj);

    /* ctx->ctxs won't be released until all ctx are freed */
    kobject_put(&ctx->ctxs->kobj);
}

static void blk_mq_hw_sysfs_release(struct kobject *kobj)
{
    struct blk_mq_hw_ctx *hctx = container_of(kobj, struct blk_mq_hw_ctx, kobj);

#if 0
    blk_free_flush_queue(hctx->fq);
#endif
    sbitmap_free(&hctx->ctx_map);
    free_cpumask_var(hctx->cpumask);
    kfree(hctx->ctxs);
    kfree(hctx);
}

static struct kobj_type blk_mq_ktype = {
    .release    = blk_mq_sysfs_release,
};

static struct kobj_type blk_mq_ctx_ktype = {
    .release    = blk_mq_ctx_sysfs_release,
};

static struct kobj_type blk_mq_hw_ktype = {
    //.sysfs_ops  = &blk_mq_hw_sysfs_ops,
    //.default_groups = default_hw_ctx_groups,
    .release    = blk_mq_hw_sysfs_release,
};

void blk_mq_sysfs_deinit(struct request_queue *q)
{
    struct blk_mq_ctx *ctx;
    int cpu;

    for_each_possible_cpu(cpu) {
        ctx = per_cpu_ptr(q->queue_ctx, cpu);
        kobject_put(&ctx->kobj);
    }
    kobject_put(q->mq_kobj);
}

void blk_mq_sysfs_init(struct request_queue *q)
{
    struct blk_mq_ctx *ctx;
    int cpu;

    kobject_init(q->mq_kobj, &blk_mq_ktype);

    for_each_possible_cpu(cpu) {
        ctx = per_cpu_ptr(q->queue_ctx, cpu);

        kobject_get(q->mq_kobj);
        kobject_init(&ctx->kobj, &blk_mq_ctx_ktype);
    }
}

void blk_mq_hctx_kobj_init(struct blk_mq_hw_ctx *hctx)
{
    kobject_init(&hctx->kobj, &blk_mq_hw_ktype);
}

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
#if 0
#include <linux/percpu-refcount.h>
#include <linux/blkzoned.h>
#endif
#include <linux/sched.h>
#include <linux/sbitmap.h>
#if 0
#include <linux/srcu.h>
#include <linux/uuid.h>
#endif
#include <linux/xarray.h>

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

extern const struct device_type disk_type;
extern struct device_type part_type;
extern struct class block_class;

#endif /* _LINUX_BLKDEV_H */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/backing-dev.h
 *
 * low-level device information and state which is propagated up through
 * to high-level code.
 */

#ifndef _LINUX_BACKING_DEV_H
#define _LINUX_BACKING_DEV_H

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/device.h>
#include <linux/writeback.h>
#include <linux/backing-dev-defs.h>
#include <linux/slab.h>

struct blkcg;

/*
 * Flags in backing_dev_info::capability
 *
 * BDI_CAP_WRITEBACK:       Supports dirty page writeback, and dirty pages
 *              should contribute to accounting
 * BDI_CAP_WRITEBACK_ACCT:  Automatically account writeback pages
 * BDI_CAP_STRICTLIMIT:     Keep number of dirty pages below bdi threshold
 */
#define BDI_CAP_WRITEBACK       (1 << 0)
#define BDI_CAP_WRITEBACK_ACCT  (1 << 1)
#define BDI_CAP_STRICTLIMIT     (1 << 2)

struct backing_dev_info *bdi_alloc(int node_id);

extern struct backing_dev_info noop_backing_dev_info;

#endif  /* _LINUX_BACKING_DEV_H */

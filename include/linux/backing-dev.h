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

__printf(2, 3)
int bdi_register(struct backing_dev_info *bdi, const char *fmt, ...);

__printf(2, 0)
int bdi_register_va(struct backing_dev_info *bdi, const char *fmt,
                    va_list args);

void bdi_set_owner(struct backing_dev_info *bdi, struct device *owner);
void bdi_unregister(struct backing_dev_info *bdi);

static inline struct backing_dev_info *bdi_get(struct backing_dev_info *bdi)
{
    kref_get(&bdi->refcnt);
    return bdi;
}

struct backing_dev_info *inode_to_bdi(struct inode *inode);

static inline bool mapping_can_writeback(struct address_space *mapping)
{
    return inode_to_bdi(mapping->host)->capabilities & BDI_CAP_WRITEBACK;
}

void bdi_put(struct backing_dev_info *bdi);

void bdi_unregister(struct backing_dev_info *bdi);

static inline struct bdi_writeback *inode_to_wb(struct inode *inode)
{
    return &inode_to_bdi(inode)->wb;
}

#endif  /* _LINUX_BACKING_DEV_H */

// SPDX-License-Identifier: GPL-2.0
#if 0
#include <linux/capability.h>
#include <linux/compat.h>
#endif
#include <linux/blkdev.h>
#include <linux/export.h>
#include <linux/gfp.h>
#if 0
#include <linux/blkpg.h>
#include <linux/hdreg.h>
#include <linux/backing-dev.h>
#include <linux/blktrace_api.h>
#include <linux/pr.h>
#endif
#include <linux/fs.h>
#include <linux/uaccess.h>
#include "blk.h"

/*
 * Always keep this in sync with compat_blkdev_ioctl()
 * to handle all incompatible commands in both functions.
 *
 * New commands must be compatible and go into blkdev_common_ioctl
 */
long blkdev_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
    panic("%s: END!\n", __func__);
}

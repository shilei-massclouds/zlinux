// SPDX-License-Identifier: GPL-2.0
/*
 * linux/fs/ext2/ioctl.c
 *
 * Copyright (C) 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include "ext2.h"
#if 0
#include <linux/capability.h>
#include <linux/time.h>
#endif
#include <linux/sched.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <asm/current.h>
#include <linux/uaccess.h>
//#include <linux/fileattr.h>

int ext2_fileattr_get(struct dentry *dentry, struct fileattr *fa)
{
    panic("%s: END!\n", __func__);
}

int ext2_fileattr_set(struct user_namespace *mnt_userns,
                      struct dentry *dentry, struct fileattr *fa)
{
    panic("%s: END!\n", __func__);
}

long ext2_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    panic("%s: END!\n", __func__);
}

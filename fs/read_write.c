// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/read_write.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/slab.h>
#include <linux/stat.h>
#if 0
#include <linux/sched/xacct.h>
#endif
#include <linux/fcntl.h>
#if 0
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#endif
#include <linux/export.h>
#if 0
#include <linux/syscalls.h>
#include <linux/splice.h>
#include <linux/compat.h>
#endif
#include <linux/pagemap.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include "internal.h"

#include <linux/uaccess.h>
//#include <asm/unistd.h>

/**
 * noop_llseek - No Operation Performed llseek implementation
 * @file:   file structure to seek on
 * @offset: file offset to seek to
 * @whence: type of seek
 *
 * This is an implementation of ->llseek useable for the rare special case when
 * userspace expects the seek to succeed but the (device) file is actually not
 * able to perform the seek. In this case you use noop_llseek() instead of
 * falling back to the default implementation of ->llseek.
 */
loff_t noop_llseek(struct file *file, loff_t offset, int whence)
{
    return file->f_pos;
}
EXPORT_SYMBOL(noop_llseek);

/**
 * generic_file_llseek - generic llseek implementation for regular files
 * @file:   file structure to seek on
 * @offset: file offset to seek to
 * @whence: type of seek
 *
 * This is a generic implemenation of ->llseek useable for all normal local
 * filesystems.  It just updates the file offset to the value specified by
 * @offset and @whence.
 */
loff_t generic_file_llseek(struct file *file, loff_t offset, int whence)
{
#if 0
    struct inode *inode = file->f_mapping->host;

    return generic_file_llseek_size(file, offset, whence,
                                    inode->i_sb->s_maxbytes,
                                    i_size_read(inode));
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(generic_file_llseek);

// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ext2/dir.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/dir.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * All code that works with directory layout had been switched to pagecache
 * and moved here. AV
 */

#include "ext2.h"
#include <linux/buffer_head.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
//#include <linux/iversion.h>

static int
ext2_readdir(struct file *file, struct dir_context *ctx)
{
    panic("%s: END!\n", __func__);
}

const struct file_operations ext2_dir_operations = {
    .llseek     = generic_file_llseek,
    .read       = generic_read_dir,
    .iterate_shared = ext2_readdir,
    .unlocked_ioctl = ext2_ioctl,
    .fsync      = ext2_fsync,
};

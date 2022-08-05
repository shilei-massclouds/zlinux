// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ext2/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *  (jj@sunsite.ms.mff.cuni.cz)
 */

//#include <linux/time.h>
#include <linux/pagemap.h>
#if 0
#include <linux/dax.h>
#include <linux/quotaops.h>
#include <linux/iomap.h>
#include <linux/uio.h>
#endif
#include "ext2.h"
#if 0
#include "xattr.h"
#include "acl.h"
#endif

int ext2_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
#if 0
    int ret;
    struct super_block *sb = file->f_mapping->host->i_sb;

    ret = generic_file_fsync(file, start, end, datasync);
    if (ret == -EIO)
        /* We don't really know where the IO error happened... */
        ext2_error(sb, __func__,
                   "detected IO error when writing metadata buffers");
    return ret;
#endif
    panic("%s: END!\n", __func__);
}

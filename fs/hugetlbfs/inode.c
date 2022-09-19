/*
 * hugetlbpage-backed filesystem.  Based on ramfs.
 *
 * Nadia Yvette Chambers, 2002
 *
 * Copyright (C) 2002 Linus Torvalds.
 * License: GPL
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/thread_info.h>
#include <asm/current.h>
#include <linux/sched/signal.h>     /* remove ASAP */
//#include <linux/falloc.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/writeback.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/string.h>
//#include <linux/capability.h>
#include <linux/ctype.h>
#include <linux/backing-dev.h>
#include <linux/hugetlb.h>
#include <linux/pagevec.h>
#include <linux/fs_parser.h>
#include <linux/mman.h>
#include <linux/slab.h>
//#include <linux/dnotify.h>
#include <linux/statfs.h>
#include <linux/security.h>
#include <linux/magic.h>
#include <linux/migrate.h>
#include <linux/uio.h>

#include <linux/uaccess.h>
#include <linux/sched/mm.h>

const struct file_operations hugetlbfs_file_operations = {
#if 0
    .read_iter      = hugetlbfs_read_iter,
    .mmap           = hugetlbfs_file_mmap,
    .fsync          = noop_fsync,
    .get_unmapped_area  = hugetlb_get_unmapped_area,
    .llseek         = default_llseek,
    .fallocate      = hugetlbfs_fallocate,
#endif
};

static int __init init_hugetlbfs_fs(void)
{
    pr_warn("%s: NO implementation!\n", __func__);
    return 0;
}
fs_initcall(init_hugetlbfs_fs)

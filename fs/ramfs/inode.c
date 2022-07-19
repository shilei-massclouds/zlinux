/*
 * Resizable simple ram filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *               2000 Transmeta Corp.
 *
 * Usage limits added by David Gibson, Linuxcare Australia.
 * This file is released under the GPL.
 */

/*
 * NOTE! This filesystem is probably most useful
 * not as a real filesystem, but as an example of
 * how virtual filesystems can be written.
 *
 * It doesn't get much simpler than this. Consider
 * that this file implements the full semantics of
 * a POSIX-compliant read-write filesystem.
 *
 * Note in particular how the filesystem does not
 * need to implement any data structures of its own
 * to keep track of the virtual data: using the VFS
 * caches is sufficient.
 */

#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#if 0
#include <linux/time.h>
#endif
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/ramfs.h>
#include <linux/sched.h>
#if 0
#include <linux/parser.h>
#endif
#include <linux/magic.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#if 0
#include <linux/seq_file.h>
#include "internal.h"
#endif

int ramfs_init_fs_context(struct fs_context *fc)
{
#if 0
    struct ramfs_fs_info *fsi;

    fsi = kzalloc(sizeof(*fsi), GFP_KERNEL);
    if (!fsi)
        return -ENOMEM;

    fsi->mount_opts.mode = RAMFS_DEFAULT_MODE;
    fc->s_fs_info = fsi;
    fc->ops = &ramfs_context_ops;
#endif
    panic("%s: END!\n", __func__);
    return 0;
}

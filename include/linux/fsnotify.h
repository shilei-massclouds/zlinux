/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FS_NOTIFY_H
#define _LINUX_FS_NOTIFY_H

/*
 * include/linux/fsnotify.h - generic hooks for filesystem notification, to
 * reduce in-source duplication from both dnotify and inotify.
 *
 * We don't compile any of this away in some complicated menagerie of ifdefs.
 * Instead, we rely on the code inside to optimize away as needed.
 *
 * (C) Copyright 2005 Robert Love
 */

#include <linux/fsnotify_backend.h>
//#include <linux/audit.h>
#include <linux/slab.h>
#include <linux/bug.h>

static inline int fsnotify_file(struct file *file, __u32 mask)
{
    const struct path *path = &file->f_path;

    if (file->f_mode & FMODE_NONOTIFY)
        return 0;

#if 0
    return fsnotify_parent(path->dentry, mask, path,
                           FSNOTIFY_EVENT_PATH);
#endif
    panic("%s: END!\n", __func__);
}

/*
 * fsnotify_open - file was opened
 */
static inline void fsnotify_open(struct file *file)
{
    __u32 mask = FS_OPEN;

    if (file->f_flags & __FMODE_EXEC)
        mask |= FS_OPEN_EXEC;

    fsnotify_file(file, mask);
}

#endif  /* _LINUX_FS_NOTIFY_H */

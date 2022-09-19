/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Filesystem access notification for Linux
 *
 *  Copyright (C) 2008 Red Hat, Inc., Eric Paris <eparis@redhat.com>
 */

#ifndef __LINUX_FSNOTIFY_BACKEND_H
#define __LINUX_FSNOTIFY_BACKEND_H

#ifdef __KERNEL__

#include <linux/idr.h> /* inotify uses this */
#include <linux/fs.h> /* struct inode */
#include <linux/list.h>
#include <linux/path.h> /* struct path */
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/user_namespace.h>
#include <linux/refcount.h>
#include <linux/mempool.h>

/*
 * IN_* from inotfy.h lines up EXACTLY with FS_*, this is so we can easily
 * convert between them.  dnotify only needs conversion at watch creation
 * so no perf loss there.  fanotify isn't defined yet, so it can use the
 * wholes if it needs more events.
 */
#define FS_ACCESS       0x00000001  /* File was accessed */
#define FS_MODIFY       0x00000002  /* File was modified */
#define FS_ATTRIB       0x00000004  /* Metadata changed */
#define FS_CLOSE_WRITE      0x00000008  /* Writtable file was closed */
#define FS_CLOSE_NOWRITE    0x00000010  /* Unwrittable file closed */
#define FS_OPEN         0x00000020  /* File was opened */
#define FS_MOVED_FROM       0x00000040  /* File was moved from X */
#define FS_MOVED_TO     0x00000080  /* File was moved to Y */
#define FS_CREATE       0x00000100  /* Subfile was created */
#define FS_DELETE       0x00000200  /* Subfile was deleted */
#define FS_DELETE_SELF      0x00000400  /* Self was deleted */
#define FS_MOVE_SELF        0x00000800  /* Self was moved */
#define FS_OPEN_EXEC        0x00001000  /* File was opened for exec */

#define FS_UNMOUNT      0x00002000  /* inode on umount fs */
#define FS_Q_OVERFLOW       0x00004000  /* Event queued overflowed */
#define FS_ERROR        0x00008000  /* Filesystem Error (fanotify) */

/* When calling fsnotify tell it if the data is a path or inode */
enum fsnotify_data_type {
    FSNOTIFY_EVENT_NONE,
    FSNOTIFY_EVENT_PATH,
    FSNOTIFY_EVENT_INODE,
    FSNOTIFY_EVENT_DENTRY,
    FSNOTIFY_EVENT_ERROR,
};

#endif  /* __KERNEL__ */

#endif  /* __LINUX_FSNOTIFY_BACKEND_H */

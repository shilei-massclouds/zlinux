/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NAMEI_H
#define _LINUX_NAMEI_H

#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/path.h>
#include <linux/fcntl.h>
#include <linux/errno.h>

/*
 * Type of the last component on LOOKUP_PARENT
 */
enum {LAST_NORM, LAST_ROOT, LAST_DOT, LAST_DOTDOT};

/* pathwalk mode */
#define LOOKUP_FOLLOW       0x0001  /* follow links at the end */
#define LOOKUP_DIRECTORY    0x0002  /* require a directory */
#define LOOKUP_AUTOMOUNT    0x0004  /* force terminal automount */
#define LOOKUP_EMPTY        0x4000  /* accept empty path [user_... only] */
#define LOOKUP_DOWN         0x8000  /* follow mounts in the starting point */
#define LOOKUP_MOUNTPOINT   0x0080  /* follow mounts in the end */

#define LOOKUP_REVAL        0x0020  /* tell ->d_revalidate() to trust no cache */
#define LOOKUP_RCU          0x0040  /* RCU pathwalk mode; semi-internal */

/* These tell filesystem methods that we are dealing with the final component... */
#define LOOKUP_OPEN         0x0100  /* ... in open */
#define LOOKUP_CREATE       0x0200  /* ... in object creation */
#define LOOKUP_EXCL         0x0400  /* ... in exclusive creation */
#define LOOKUP_RENAME_TARGET    0x0800  /* ... in destination of rename() */

/* internal use only */
#define LOOKUP_PARENT       0x0010

/* Scoping flags for lookup. */
#define LOOKUP_NO_SYMLINKS  0x010000 /* No symlink crossing. */
#define LOOKUP_NO_MAGICLINKS    0x020000 /* No nd_jump_link() crossing. */
#define LOOKUP_NO_XDEV      0x040000 /* No mountpoint crossing. */
#define LOOKUP_BENEATH      0x080000 /* No escaping from starting point. */
#define LOOKUP_IN_ROOT      0x100000 /* Treat dirfd as fs root. */
#define LOOKUP_CACHED       0x200000 /* Only do cached lookup */
/* LOOKUP_* flags which do scope-related checks based on the dirfd. */
#define LOOKUP_IS_SCOPED (LOOKUP_BENEATH | LOOKUP_IN_ROOT)

extern struct dentry *
kern_path_create(int, const char *, struct path *, unsigned int);

extern void done_path_create(struct path *, struct dentry *);

extern int kern_path(const char *, unsigned, struct path *);

#endif /* _LINUX_NAMEI_H */

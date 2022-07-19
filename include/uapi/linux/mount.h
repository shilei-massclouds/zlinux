#ifndef _UAPI_LINUX_MOUNT_H
#define _UAPI_LINUX_MOUNT_H

#include <linux/types.h>

/*
 * These are the fs-independent mount-flags: up to 32 flags are supported
 *
 * Usage of these is restricted within the kernel to core mount(2) code and
 * callers of sys_mount() only.  Filesystems should be using the SB_*
 * equivalent instead.
 */
#define MS_RDONLY    1  /* Mount read-only */
#define MS_NOSUID    2  /* Ignore suid and sgid bits */
#define MS_NODEV     4  /* Disallow access to device special files */
#define MS_NOEXEC    8  /* Disallow program execution */
#define MS_SYNCHRONOUS  16  /* Writes are synced at once */
#define MS_REMOUNT  32  /* Alter flags of a mounted FS */
#define MS_MANDLOCK 64  /* Allow mandatory locks on an FS */
#define MS_DIRSYNC  128 /* Directory modifications are synchronous */
#define MS_NOSYMFOLLOW  256 /* Do not follow symlinks */
#define MS_NOATIME  1024    /* Do not update access times. */
#define MS_NODIRATIME   2048    /* Do not update directory access times */
#define MS_BIND     4096
#define MS_MOVE     8192
#define MS_REC      16384
#define MS_VERBOSE  32768   /* War is peace. Verbosity is silence.
                   MS_VERBOSE is deprecated. */
#define MS_SILENT   32768

#endif /* _UAPI_LINUX_MOUNT_H */

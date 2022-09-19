/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_FCNTL_H
#define _UAPI_LINUX_FCNTL_H

#include <asm/fcntl.h>
#include <linux/openat2.h>

/*
 * Valid hint values for F_{GET,SET}_RW_HINT. 0 is "not set", or can be
 * used to clear any hints previously set.
 */
#define RWH_WRITE_LIFE_NOT_SET  0
#define RWH_WRITE_LIFE_NONE     1
#define RWH_WRITE_LIFE_SHORT    2
#define RWH_WRITE_LIFE_MEDIUM   3
#define RWH_WRITE_LIFE_LONG     4
#define RWH_WRITE_LIFE_EXTREME  5

/*
 * Types of seals
 */
#define F_SEAL_SEAL     0x0001  /* prevent further seals from being set */
#define F_SEAL_SHRINK   0x0002  /* prevent file from shrinking */
#define F_SEAL_GROW     0x0004  /* prevent file from growing */
#define F_SEAL_WRITE    0x0008  /* prevent writes */
#define F_SEAL_FUTURE_WRITE 0x0010  /* prevent future writes while mapped */
/* (1U << 31) is reserved for signed error codes */

/*
 * The constants AT_REMOVEDIR and AT_EACCESS have the same value.  AT_EACCESS is
 * meaningful only to faccessat, while AT_REMOVEDIR is meaningful only to
 * unlinkat.  The two functions do completely different things and therefore,
 * the flags can be allowed to overlap.  For example, passing AT_REMOVEDIR to
 * faccessat would be undefined behavior and thus treating it equivalent to
 * AT_EACCESS is valid undefined behavior.
 */
#define AT_FDCWD        -100    /* Special value used to indicate
                                           openat should use the current
                                           working directory. */
#define AT_SYMLINK_NOFOLLOW 0x100   /* Do not follow symbolic links.  */
#define AT_EACCESS      0x200   /* Test access permitted for
                                           effective IDs, not real IDs.  */
#define AT_REMOVEDIR        0x200   /* Remove directory instead of
                                           unlinking file.  */
#define AT_SYMLINK_FOLLOW   0x400   /* Follow symbolic links.  */
#define AT_NO_AUTOMOUNT     0x800   /* Suppress terminal automount traversal */
#define AT_EMPTY_PATH       0x1000  /* Allow empty relative pathname */

#define AT_STATX_SYNC_TYPE  0x6000  /* Type of synchronisation required from statx() */
#define AT_STATX_SYNC_AS_STAT   0x0000  /* - Do whatever stat() does */
#define AT_STATX_FORCE_SYNC 0x2000  /* - Force the attributes to be sync'd with the server */
#define AT_STATX_DONT_SYNC  0x4000  /* - Don't sync attributes with the server */

#define AT_RECURSIVE    0x8000  /* Apply to the entire subtree */

#endif /* _UAPI_LINUX_FCNTL_H */

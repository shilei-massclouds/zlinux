/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_STAT_H
#define _UAPI_LINUX_STAT_H

#include <linux/types.h>

#if defined(__KERNEL__) || !defined(__GLIBC__) || (__GLIBC__ < 2)

#define S_IFMT  00170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000
#define S_ISUID  0004000
#define S_ISGID  0002000
#define S_ISVTX  0001000

#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

/*
 * Flags to be stx_mask
 *
 * Query request/result mask for statx() and struct statx::stx_mask.
 *
 * These bits should be set in the mask argument of statx() to request
 * particular items when calling statx().
 */
#define STATX_TYPE      0x00000001U /* Want/got stx_mode & S_IFMT */
#define STATX_MODE      0x00000002U /* Want/got stx_mode & ~S_IFMT */
#define STATX_NLINK     0x00000004U /* Want/got stx_nlink */
#define STATX_UID       0x00000008U /* Want/got stx_uid */
#define STATX_GID       0x00000010U /* Want/got stx_gid */
#define STATX_ATIME     0x00000020U /* Want/got stx_atime */
#define STATX_MTIME     0x00000040U /* Want/got stx_mtime */
#define STATX_CTIME     0x00000080U /* Want/got stx_ctime */
#define STATX_INO       0x00000100U /* Want/got stx_ino */
#define STATX_SIZE      0x00000200U /* Want/got stx_size */
#define STATX_BLOCKS        0x00000400U /* Want/got stx_blocks */
#define STATX_BASIC_STATS   0x000007ffU /* The stuff in the normal stat struct */
#define STATX_BTIME     0x00000800U /* Want/got stx_btime */
#define STATX_MNT_ID        0x00001000U /* Got stx_mnt_id */

#define STATX__RESERVED     0x80000000U /* Reserved for future struct statx expansion */

#endif

#endif /* _UAPI_LINUX_STAT_H */

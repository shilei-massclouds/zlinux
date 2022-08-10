/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_FS_H
#define _UAPI_LINUX_FS_H

/*
 * This file has definitions for some important file table structures
 * and constants and structures used by various generic file system
 * ioctl's.  Please do not make any changes in this file before
 * sending patches for review to linux-fsdevel@vger.kernel.org and
 * linux-api@vger.kernel.org.
 */

#include <linux/limits.h>
//#include <linux/ioctl.h>
#include <linux/types.h>
#ifndef __KERNEL__
#include <linux/fscrypt.h>
#endif

/* Use of MS_* flags within the kernel is restricted to core mount(2) code. */
#if !defined(__KERNEL__)
#include <linux/mount.h>
#endif

/*
 * It's silly to have NR_OPEN bigger than NR_FILE, but you can change
 * the file limit at runtime and only root can increase the per-process
 * nr_file rlimit, so it's safe to set up a ridiculously high absolute
 * upper limit on files-per-process.
 *
 * Some programs (notably those using select()) may have to be
 * recompiled to take full advantage of the new limits..
 */

/* Fixed constants first: */
#undef NR_OPEN
#define INR_OPEN_CUR 1024   /* Initial setting for nfile rlimits */
#define INR_OPEN_MAX 4096   /* Hard limit for nfile rlimits */

#define BLOCK_SIZE_BITS 10
#define BLOCK_SIZE (1<<BLOCK_SIZE_BITS)

#define NR_FILE  8192   /* this can well be larger on a larger system */

/*
 * Inode flags (FS_IOC_GETFLAGS / FS_IOC_SETFLAGS)
 *
 * Note: for historical reasons, these flags were originally used and
 * defined for use by ext2/ext3, and then other file systems started
 * using these flags so they wouldn't need to write their own version
 * of chattr/lsattr (which was shipped as part of e2fsprogs).  You
 * should think twice before trying to use these flags in new
 * contexts, or trying to assign these flags, since they are used both
 * as the UAPI and the on-disk encoding for ext2/3/4.  Also, we are
 * almost out of 32-bit flags.  :-)
 *
 * We have recently hoisted FS_IOC_FSGETXATTR / FS_IOC_FSSETXATTR from
 * XFS to the generic FS level interface.  This uses a structure that
 * has padding and hence has more room to grow, so it may be more
 * appropriate for many new use cases.
 *
 * Please do not change these flags or interfaces before checking with
 * linux-fsdevel@vger.kernel.org and linux-api@vger.kernel.org.
 */
#define FS_SECRM_FL             0x00000001 /* Secure deletion */
#define FS_UNRM_FL              0x00000002 /* Undelete */
#define FS_COMPR_FL             0x00000004 /* Compress file */
#define FS_SYNC_FL              0x00000008 /* Synchronous updates */
#define FS_IMMUTABLE_FL         0x00000010 /* Immutable file */
#define FS_APPEND_FL            0x00000020 /* writes to file may only append */
#define FS_NODUMP_FL            0x00000040 /* do not dump file */
#define FS_NOATIME_FL           0x00000080 /* do not update atime */
/* Reserved for compression usage... */
#define FS_DIRTY_FL             0x00000100
#define FS_COMPRBLK_FL          0x00000200 /* One or more compressed clusters */
#define FS_NOCOMP_FL            0x00000400 /* Don't compress */
/* End compression flags --- maybe not all used */
#define FS_ENCRYPT_FL           0x00000800 /* Encrypted file */
#define FS_BTREE_FL             0x00001000 /* btree format dir */
#define FS_INDEX_FL             0x00001000 /* hash-indexed directory */
#define FS_IMAGIC_FL            0x00002000 /* AFS directory */
#define FS_JOURNAL_DATA_FL      0x00004000 /* Reserved for ext3 */
#define FS_NOTAIL_FL            0x00008000 /* file tail should not be merged */
#define FS_DIRSYNC_FL           0x00010000 /* dirsync behaviour (directories only) */
#define FS_TOPDIR_FL            0x00020000 /* Top of directory hierarchies*/
#define FS_HUGE_FILE_FL         0x00040000 /* Reserved for ext4 */
#define FS_EXTENT_FL            0x00080000 /* Extents */
#define FS_VERITY_FL            0x00100000 /* Verity protected inode */
#define FS_EA_INODE_FL          0x00200000 /* Inode used for large EA */
#define FS_EOFBLOCKS_FL         0x00400000 /* Reserved for ext4 */
#define FS_NOCOW_FL             0x00800000 /* Do not cow file */
#define FS_DAX_FL               0x02000000 /* Inode is DAX */
#define FS_INLINE_DATA_FL       0x10000000 /* Reserved for ext4 */
#define FS_PROJINHERIT_FL       0x20000000 /* Create with parents projid */
#define FS_CASEFOLD_FL          0x40000000 /* Folder is case insensitive */
#define FS_RESERVED_FL          0x80000000 /* reserved for ext2 lib */

/* And dynamically-tunable limits and defaults: */
struct files_stat_struct {
    unsigned long nr_files;         /* read only */
    unsigned long nr_free_files;    /* read only */
    unsigned long max_files;        /* tunable */
};

#endif /* _UAPI_LINUX_FS_H */

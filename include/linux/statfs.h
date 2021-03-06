/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_STATFS_H
#define _LINUX_STATFS_H

#include <linux/types.h>
#if 0
#include <asm/statfs.h>
#endif
#include <asm/byteorder.h>

struct kstatfs {
    long f_type;
    long f_bsize;
    u64 f_blocks;
    u64 f_bfree;
    u64 f_bavail;
    u64 f_files;
    u64 f_ffree;
    __kernel_fsid_t f_fsid;
    long f_namelen;
    long f_frsize;
    long f_flags;
    long f_spare[4];
};

#endif /* _LINUX_STATFS_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_STAT_H
#define _LINUX_STAT_H

#include <asm/stat.h>
#include <uapi/linux/stat.h>
#include <linux/uidgid.h>

#define S_IRWXUGO   (S_IRWXU|S_IRWXG|S_IRWXO)
#define S_IALLUGO   (S_ISUID|S_ISGID|S_ISVTX|S_IRWXUGO)
#define S_IRUGO     (S_IRUSR|S_IRGRP|S_IROTH)
#define S_IWUGO     (S_IWUSR|S_IWGRP|S_IWOTH)
#define S_IXUGO     (S_IXUSR|S_IXGRP|S_IXOTH)

struct kstat {
    u32         result_mask;    /* What fields the user got */
    umode_t     mode;
    unsigned int    nlink;
    uint32_t    blksize;    /* Preferred I/O size */
    u64     attributes;
    u64     attributes_mask;
#if 0
#define KSTAT_ATTR_FS_IOC_FLAGS             \
    (STATX_ATTR_COMPRESSED |            \
     STATX_ATTR_IMMUTABLE |             \
     STATX_ATTR_APPEND |                \
     STATX_ATTR_NODUMP |                \
     STATX_ATTR_ENCRYPTED |             \
     STATX_ATTR_VERITY              \
     )/* Attrs corresponding to FS_*_FL flags */
#define KSTAT_ATTR_VFS_FLAGS                \
    (STATX_ATTR_IMMUTABLE |             \
     STATX_ATTR_APPEND              \
     ) /* Attrs corresponding to S_* flags that are enforced by the VFS */
#endif
    u64     ino;
    dev_t       dev;
    dev_t       rdev;
    kuid_t      uid;
    kgid_t      gid;
    loff_t      size;
#if 0
    struct timespec64 atime;
    struct timespec64 mtime;
    struct timespec64 ctime;
    struct timespec64 btime;            /* File creation time */
#endif
    u64     blocks;
    u64     mnt_id;
};

#endif /* _LINUX_STAT_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KDEV_T_H
#define _LINUX_KDEV_T_H

#if 0
#include <uapi/linux/kdev_t.h>
#endif

#define MINORBITS   20
#define MINORMASK   ((1U << MINORBITS) - 1)

#define MAJOR(dev)      ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)      ((unsigned int) ((dev) & MINORMASK))
#define MKDEV(ma,mi)    (((ma) << MINORBITS) | (mi))

static __always_inline u32 new_encode_dev(dev_t dev)
{
    unsigned major = MAJOR(dev);
    unsigned minor = MINOR(dev);
    return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

static __always_inline dev_t new_decode_dev(u32 dev)
{
    unsigned major = (dev & 0xfff00) >> 8;
    unsigned minor = (dev & 0xff) | ((dev >> 12) & 0xfff00);
    return MKDEV(major, minor);
}

/* acceptable for old filesystems */
static __always_inline bool old_valid_dev(dev_t dev)
{
    return MAJOR(dev) < 256 && MINOR(dev) < 256;
}

#endif /* _LINUX_KDEV_T_H */

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

#endif /* _LINUX_KDEV_T_H */

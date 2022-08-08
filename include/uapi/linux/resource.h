/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_RESOURCE_H
#define _UAPI_LINUX_RESOURCE_H

//#include <linux/time.h>
#include <linux/types.h>

/*
 * Resource control/accounting header file for linux
 */

struct rlimit {
    __kernel_ulong_t    rlim_cur;
    __kernel_ulong_t    rlim_max;
};

#define RLIM64_INFINITY     (~0ULL)

struct rlimit64 {
    __u64 rlim_cur;
    __u64 rlim_max;
};

/*
 * Limit the stack by to some sane default: root can always
 * increase this limit if needed..  8MB seems reasonable.
 */
#define _STK_LIM    (8*1024*1024)

/*
 * Limit the amount of locked memory by some sane default:
 * root can always increase this limit if needed.
 *
 * The main use-cases are (1) preventing sensitive memory
 * from being swapped; (2) real-time operations; (3) via
 * IOURING_REGISTER_BUFFERS.
 *
 * The first two don't need much. The latter will take as
 * much as it can get. 8MB is a reasonably sane default.
 */
#define MLOCK_LIMIT (8*1024*1024)

/*
 * Due to binary compatibility, the actual resource numbers
 * may be different for different linux versions..
 */
#include <asm/resource.h>

#endif /* _UAPI_LINUX_RESOURCE_H */

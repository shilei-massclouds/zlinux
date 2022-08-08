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
 * Due to binary compatibility, the actual resource numbers
 * may be different for different linux versions..
 */
//#include <asm/resource.h>

#endif /* _UAPI_LINUX_RESOURCE_H */

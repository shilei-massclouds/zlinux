/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_TIME_TYPES_H
#define _UAPI_LINUX_TIME_TYPES_H

#include <linux/types.h>

struct __kernel_timespec {
    __kernel_time64_t       tv_sec;                 /* seconds */
    long long               tv_nsec;                /* nanoseconds */
};

/*
 * legacy timeval structure, only embedded in structures that
 * traditionally used 'timeval' to pass time intervals (not absolute
 * times). Do not add new users. If user space fails to compile
 * here, this is probably because it is not y2038 safe and needs to
 * be changed to use another interface.
 */
#ifndef __kernel_old_timeval
struct __kernel_old_timeval {
    __kernel_long_t tv_sec;
    __kernel_long_t tv_usec;
};
#endif

#endif /* _UAPI_LINUX_TIME_TYPES_H */

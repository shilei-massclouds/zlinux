/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TIME64_H
#define _LINUX_TIME64_H

#include <linux/math64.h>
//#include <vdso/time64.h>

typedef __s64 time64_t;
typedef __u64 timeu64_t;

//#include <uapi/linux/time.h>

/* Located here for timespec[64]_valid_strict */
#define TIME64_MAX      ((s64)~((u64)1 << 63))
#define TIME64_MIN      (-TIME64_MAX - 1)

#endif /* _LINUX_TIME64_H */

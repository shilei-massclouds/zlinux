/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __ASM_GENERIC_POSIX_TYPES_H
#define __ASM_GENERIC_POSIX_TYPES_H

#include <asm/bitsperlong.h>

#ifndef __kernel_pid_t
typedef int __kernel_pid_t;
#endif

#ifndef __kernel_long_t
typedef long            __kernel_long_t;
typedef unsigned long   __kernel_ulong_t;
#endif

#ifndef __kernel_fsid_t
typedef struct {
    int val[2];
} __kernel_fsid_t;
#endif

/*
 * Most 32 bit architectures use "unsigned int" size_t,
 * and all 64 bit architectures use "unsigned long" size_t.
 */
#ifndef __kernel_size_t
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_long_t __kernel_ssize_t;
typedef __kernel_long_t __kernel_ptrdiff_t;
#endif /* !__kernel_size_t */

#ifndef __kernel_mode_t
typedef unsigned int    __kernel_mode_t;
#endif

#ifndef __kernel_uid_t
typedef unsigned int    __kernel_uid_t;
typedef unsigned int    __kernel_gid_t;
#endif

#ifndef __kernel_uid32_t
typedef unsigned int    __kernel_uid32_t;
typedef unsigned int    __kernel_gid32_t;
#endif

typedef unsigned short  __kernel_uid16_t;
typedef unsigned short  __kernel_gid16_t;

typedef long long       __kernel_loff_t;

typedef long long __kernel_time64_t;
typedef __kernel_long_t __kernel_clock_t;
typedef int __kernel_timer_t;
typedef int __kernel_clockid_t;

#endif /* __ASM_GENERIC_POSIX_TYPES_H */

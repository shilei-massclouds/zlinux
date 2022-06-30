/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _ASM_GENERIC_ERRNO_BASE_H
#define _ASM_GENERIC_ERRNO_BASE_H

#define EPERM       1   /* Operation not permitted */
#define ENOENT      2   /* No such file or directory */
#define EINTR       4   /* Interrupted system call */
#define ENXIO       6   /* No such device or address */
#define E2BIG       7   /* Argument list too long */
#define EAGAIN      11  /* Try again */
#define ENOMEM      12  /* Out of memory */
#define EFAULT      14  /* Bad address */
#define EBUSY       16  /* Device or resource busy */
#define EEXIST      17  /* File exists */
#define ENODEV      19  /* No such device */
#define EINVAL      22  /* Invalid argument */
#define ENOSPC      28  /* No space left on device */

#endif /* _ASM_GENERIC_ERRNO_BASE_H */

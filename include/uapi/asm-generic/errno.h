/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _ASM_GENERIC_ERRNO_H
#define _ASM_GENERIC_ERRNO_H

#include <asm-generic/errno-base.h>

#define EDEADLK         35  /* Resource deadlock would occur */
#define ENAMETOOLONG    36  /* File name too long */
#define ENOLCK          37  /* No record locks available */

/*
 * This error code is special: arch syscall entry code will return
 * -ENOSYS if users try to call a syscall that doesn't exist.  To keep
 * failures of syscalls that really do exist distinguishable from
 * failures due to attempts to use a nonexistent syscall, syscall
 * implementations should refrain from returning -ENOSYS.
 */
#define ENOSYS      38  /* Invalid system call number */
#define ENOTEMPTY   39  /* Directory not empty */
#define ELOOP       40  /* Too many symbolic links encountered */
#define EBADE       52  /* Invalid exchange */

#define ENODATA     61  /* No data available */
#define ETIME       62  /* Timer expired */
#define ENOLINK     67  /* Link has been severed */
#define EOVERFLOW   75  /* Value too large for defined data type */
#define EREMCHG     78  /* Remote address changed */
#define ELIBBAD     80  /* Accessing a corrupted shared library */
#define EILSEQ      84  /* Illegal byte sequence */
#define EOPNOTSUPP  95  /* Operation not supported on transport endpoint */
#define ENOTCONN    107 /* Transport endpoint is not connected */

#define ETOOMANYREFS    109 /* Too many references: cannot splice */

#define ETIMEDOUT   110 /* Connection timed out */
#define EALREADY    114 /* Operation already in progress */
#define ESTALE      116 /* Stale file handle */
#define EUCLEAN     117 /* Structure needs cleaning */
#define EREMOTEIO   121 /* Remote I/O error */

#define ENOTRECOVERABLE 131 /* State not recoverable */

#define EHWPOISON   133 /* Memory page has hardware error */

#endif /* _ASM_GENERIC_ERRNO_H */

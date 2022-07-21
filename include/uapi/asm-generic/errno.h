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

#define ENODATA     61  /* No data available */
#define ETIME       62  /* Timer expired */
#define EOVERFLOW   75  /* Value too large for defined data type */
#define EILSEQ      84  /* Illegal byte sequence */
#define ENOTCONN    107 /* Transport endpoint is not connected */
#define EALREADY    114 /* Operation already in progress */
#define ESTALE      116 /* Stale file handle */

#define ENOTRECOVERABLE 131 /* State not recoverable */

#endif /* _ASM_GENERIC_ERRNO_H */

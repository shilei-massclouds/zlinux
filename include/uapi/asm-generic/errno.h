/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _ASM_GENERIC_ERRNO_H
#define _ASM_GENERIC_ERRNO_H

#include <asm-generic/errno-base.h>

#define ENODATA     61  /* No data available */
#define ETIME       62  /* Timer expired */
#define EOVERFLOW   75  /* Value too large for defined data type */
#define EILSEQ      84  /* Illegal byte sequence */
#define EALREADY    114 /* Operation already in progress */

#endif /* _ASM_GENERIC_ERRNO_H */

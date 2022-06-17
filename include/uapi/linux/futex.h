/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_FUTEX_H
#define _UAPI_LINUX_FUTEX_H

#include <linux/compiler.h>
#include <linux/types.h>

/* Second argument to futex syscall */

/*
 * The rest of the robust-futex field is for the TID:
 */
#define FUTEX_TID_MASK  0x3fffffff

#endif /* _UAPI_LINUX_FUTEX_H */

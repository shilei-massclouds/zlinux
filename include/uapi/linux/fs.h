/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_FS_H
#define _UAPI_LINUX_FS_H

/*
 * This file has definitions for some important file table structures
 * and constants and structures used by various generic file system
 * ioctl's.  Please do not make any changes in this file before
 * sending patches for review to linux-fsdevel@vger.kernel.org and
 * linux-api@vger.kernel.org.
 */

#include <linux/limits.h>
//#include <linux/ioctl.h>
#include <linux/types.h>
#ifndef __KERNEL__
#include <linux/fscrypt.h>
#endif

/* Use of MS_* flags within the kernel is restricted to core mount(2) code. */
#if !defined(__KERNEL__)
#include <linux/mount.h>
#endif

#define BLOCK_SIZE_BITS 10
#define BLOCK_SIZE (1<<BLOCK_SIZE_BITS)

#endif /* _UAPI_LINUX_FS_H */

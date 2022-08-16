/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_COMPAT_H
#define _LINUX_COMPAT_H
/*
 * These are the type definitions for the architecture specific
 * syscall compatibility layer.
 */

#include <linux/types.h>
//#include <linux/time.h>

//#include <linux/stat.h>
#include <linux/param.h>    /* for HZ */
#if 0
#include <linux/sem.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/aio_abi.h>  /* for aio_context_t */
#endif
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>

#if 0
#include <asm/compat.h>
#include <asm/signal.h>
#endif
#include <asm/siginfo.h>

#endif /* _LINUX_COMPAT_H */

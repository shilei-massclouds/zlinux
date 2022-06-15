/* SPDX-License-Identifier: GPL-2.0 */
/* thread_info.h: common low-level thread information accessors
 *
 * Copyright (C) 2002  David Howells (dhowells@redhat.com)
 * - Incorporating suggestions made by Linus Torvalds
 */

#ifndef _LINUX_THREAD_INFO_H
#define _LINUX_THREAD_INFO_H

#include <linux/types.h>
#include <linux/bug.h>
#include <linux/bitops.h>

#include <asm/thread_info.h>
#include <asm/current.h>

#define current_thread_info() ((struct thread_info *)current)

#ifdef __KERNEL__

#define THREADINFO_GFP  (GFP_KERNEL_ACCOUNT | __GFP_ZERO)

#endif /* __KERNEL__ */

#endif /* _LINUX_THREAD_INFO_H */

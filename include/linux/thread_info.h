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

/*
 * flag set/clear/test wrappers
 * - pass TIF_xxxx constants to these functions
 */

static inline void set_ti_thread_flag(struct thread_info *ti, int flag)
{
    set_bit(flag, (unsigned long *)&ti->flags);
}

static inline void clear_ti_thread_flag(struct thread_info *ti, int flag)
{
    clear_bit(flag, (unsigned long *)&ti->flags);
}

static inline int test_ti_thread_flag(struct thread_info *ti, int flag)
{
    return test_bit(flag, (unsigned long *)&ti->flags);
}

#define test_thread_flag(flag) \
    test_ti_thread_flag(current_thread_info(), flag)

#define tif_need_resched() test_thread_flag(TIF_NEED_RESCHED)

#endif /* __KERNEL__ */

#endif /* _LINUX_THREAD_INFO_H */

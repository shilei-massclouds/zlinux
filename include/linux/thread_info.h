/* SPDX-License-Identifier: GPL-2.0 */
/* thread_info.h: common low-level thread information accessors
 *
 * Copyright (C) 2002  David Howells (dhowells@redhat.com)
 * - Incorporating suggestions made by Linus Torvalds
 */

#ifndef _LINUX_THREAD_INFO_H
#define _LINUX_THREAD_INFO_H

#include <linux/types.h>
#include <linux/limits.h>
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

#define tif_need_resched() test_thread_flag(TIF_NEED_RESCHED)

static inline void check_object_size(const void *ptr, unsigned long n,
                                     bool to_user)
{ }

extern void __compiletime_error("copy source size is too small")
__bad_copy_from(void);
extern void __compiletime_error("copy destination size is too small")
__bad_copy_to(void);

static inline void copy_overflow(int size, unsigned long count)
{
#if 0
    if (IS_ENABLED(CONFIG_BUG))
        __copy_overflow(size, count);
#endif
}

static __always_inline __must_check bool
check_copy_size(const void *addr, size_t bytes, bool is_source)
{
    int sz = __builtin_object_size(addr, 0);
    if (unlikely(sz >= 0 && sz < bytes)) {
        if (!__builtin_constant_p(bytes))
            copy_overflow(sz, bytes);
        else if (is_source)
            __bad_copy_from();
        else
            __bad_copy_to();
        return false;
    }
    if (WARN_ON_ONCE(bytes > INT_MAX))
        return false;
    check_object_size(addr, bytes, is_source);
    return true;
}

#define set_thread_flag(flag) \
    set_ti_thread_flag(current_thread_info(), flag)
#define clear_thread_flag(flag) \
    clear_ti_thread_flag(current_thread_info(), flag)
#define update_thread_flag(flag, value) \
    update_ti_thread_flag(current_thread_info(), flag, value)
#define test_and_set_thread_flag(flag) \
    test_and_set_ti_thread_flag(current_thread_info(), flag)
#define test_and_clear_thread_flag(flag) \
    test_and_clear_ti_thread_flag(current_thread_info(), flag)
#define test_thread_flag(flag) \
    test_ti_thread_flag(current_thread_info(), flag)
#define read_thread_flags() \
    read_ti_thread_flags(current_thread_info())

#endif /* __KERNEL__ */

#endif /* _LINUX_THREAD_INFO_H */

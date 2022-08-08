/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_UACCESS_H__
#define __LINUX_UACCESS_H__

#include <linux/sched.h>
#include <linux/thread_info.h>

#include <asm/uaccess.h>

static __always_inline void pagefault_disabled_inc(void)
{
    current->pagefault_disabled++;
}

static __always_inline void pagefault_disabled_dec(void)
{
    current->pagefault_disabled--;
}

/*
 * These routines enable/disable the pagefault handler. If disabled, it will
 * not take any locks and go straight to the fixup table.
 *
 * User access methods will not sleep when called from a pagefault_disabled()
 * environment.
 */
static inline void pagefault_disable(void)
{
    pagefault_disabled_inc();
    /*
     * make sure to have issued the store before a pagefault
     * can hit.
     */
    barrier();
}

static inline void pagefault_enable(void)
{
    /*
     * make sure to issue those last loads/stores before enabling
     * the pagefault handler again.
     */
    barrier();
    pagefault_disabled_dec();
}

#endif /* __LINUX_UACCESS_H__ */

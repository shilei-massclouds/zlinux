// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * printk_safe.c - Safe printk for printk-deadlock-prone contexts
 */

#include <linux/preempt.h>
#include <linux/spinlock.h>
//#include <linux/kdb.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
/*
#include <linux/irq_work.h>
#include <linux/kprobes.h>
*/
#include <linux/printk.h>
#include <linux/percpu.h>

#include "internal.h"

static DEFINE_PER_CPU(int, printk_context);

__printf(1, 0) int vprintk_func(const char *fmt, va_list args)
{
#if 0
    /*
     * Try to use the main logbuf even in NMI. But avoid calling console
     * drivers that might have their own locks.
     */
    if ((this_cpu_read(printk_context) & PRINTK_NMI_DIRECT_CONTEXT_MASK) &&
        raw_spin_trylock(&logbuf_lock)) {
        int len;

        len = vprintk_store(0, LOGLEVEL_DEFAULT, NULL, 0, fmt, args);
        raw_spin_unlock(&logbuf_lock);
        defer_console_output();
        return len;
    }

    /* Use extra buffer in NMI when logbuf_lock is taken or in safe mode. */
    if (this_cpu_read(printk_context) & PRINTK_NMI_CONTEXT_MASK)
        return vprintk_nmi(fmt, args);

    /* Use extra buffer to prevent a recursion deadlock in safe mode. */
    if (this_cpu_read(printk_context) & PRINTK_SAFE_CONTEXT_MASK)
        return vprintk_safe(fmt, args);
#endif

    /* No obstacles. */
    return vprintk_default(fmt, args);
}

/* Can be preempted by NMI. */
void __printk_safe_enter(void)
{
    this_cpu_inc(printk_context);
}

/* Can be preempted by NMI. */
void __printk_safe_exit(void)
{
    this_cpu_dec(printk_context);
}

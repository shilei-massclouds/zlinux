// SPDX-License-Identifier: GPL-2.0

//#include <linux/kernel_stat.h>
#include <linux/export.h>
//#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/mm.h>
#if 0
#include <linux/swap.h>
#include <linux/pid_namespace.h>
#include <linux/notifier.h>
#endif
#include <linux/thread_info.h>
#include <linux/jiffies.h>
#if 0
#include <linux/time.h>
#endif
#include <linux/timer.h>
#include <linux/posix-timers.h>
#include <linux/cpu.h>
#if 0
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <linux/tick.h>
#include <linux/kallsyms.h>
#include <linux/irq_work.h>
#include <linux/sched/signal.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/nohz.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/random.h>
#endif
#include <linux/sched/debug.h>

#include <linux/uaccess.h>
//#include <asm/unistd.h>
#include <asm/div64.h>
//#include <asm/timex.h>
//#include <asm/io.h>

//#include "tick-internal.h"

__visible u64 jiffies_64 __cacheline_aligned_in_smp = INITIAL_JIFFIES;

EXPORT_SYMBOL(jiffies_64);

/*
 * Since schedule_timeout()'s timer is defined on the stack, it must store
 * the target task on the stack as well.
 */
struct process_timer {
    struct timer_list timer;
    struct task_struct *task;
};

/**
 * schedule_timeout - sleep until timeout
 * @timeout: timeout value in jiffies
 *
 * Make the current task sleep until @timeout jiffies have elapsed.
 * The function behavior depends on the current task state
 * (see also set_current_state() description):
 *
 * %TASK_RUNNING - the scheduler is called, but the task does not sleep
 * at all. That happens because sched_submit_work() does nothing for
 * tasks in %TASK_RUNNING state.
 *
 * %TASK_UNINTERRUPTIBLE - at least @timeout jiffies are guaranteed to
 * pass before the routine returns unless the current task is explicitly
 * woken up, (e.g. by wake_up_process()).
 *
 * %TASK_INTERRUPTIBLE - the routine may return early if a signal is
 * delivered to the current task or the current task is explicitly woken
 * up.
 *
 * The current task state is guaranteed to be %TASK_RUNNING when this
 * routine returns.
 *
 * Specifying a @timeout value of %MAX_SCHEDULE_TIMEOUT will schedule
 * the CPU away without a bound on the timeout. In this case the return
 * value will be %MAX_SCHEDULE_TIMEOUT.
 *
 * Returns 0 when the timer has expired otherwise the remaining time in
 * jiffies will be returned. In all cases the return value is guaranteed
 * to be non-negative.
 */
signed long __sched schedule_timeout(signed long timeout)
{
    struct process_timer timer;
    unsigned long expire;

    switch (timeout)
    {
    case MAX_SCHEDULE_TIMEOUT:
        /*
         * These two special cases are useful to be comfortable
         * in the caller. Nothing more. We could take
         * MAX_SCHEDULE_TIMEOUT from one of the negative value
         * but I' d like to return a valid offset (>=0) to allow
         * the caller to do everything it want with the retval.
         */
        schedule();
        goto out;
    default:
        /*
         * Another bit of PARANOID. Note that the retval will be
         * 0 since no piece of kernel is supposed to do a check
         * for a negative retval of schedule_timeout() (since it
         * should never happens anyway). You just have the printk()
         * that will tell you if something is gone wrong and where.
         */
        if (timeout < 0) {
            printk(KERN_ERR "schedule_timeout: wrong timeout "
                   "value %lx\n", timeout);
            //dump_stack();
            __set_current_state(TASK_RUNNING);
            goto out;
        }
    }
    panic("%s: NOT-implemented!\n", __func__);
    return 0;

 out:
    return timeout < 0 ? 0 : timeout;
}

signed long __sched schedule_timeout_uninterruptible(signed long timeout)
{
    panic("%s: NO implemented!\n", __func__);
#if 0
    __set_current_state(TASK_UNINTERRUPTIBLE);
    return schedule_timeout(timeout);
#endif
}
EXPORT_SYMBOL(schedule_timeout_uninterruptible);

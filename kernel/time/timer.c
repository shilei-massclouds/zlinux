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
#include <linux/posix-timers.h>
#endif
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

signed long __sched schedule_timeout(signed long timeout)
{
    panic("%s: NOT-implemented!\n", __func__);
    return 0;
}

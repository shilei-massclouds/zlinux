/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Scheduler internal types and methods:
 */
#ifndef _KERNEL_SCHED_SCHED_H
#define _KERNEL_SCHED_SCHED_H

#if 0
#include <linux/sched/affinity.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/cpufreq.h>
#include <linux/sched/deadline.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/mm.h>
#include <linux/sched/rseq_api.h>
#include <linux/sched/signal.h>
#include <linux/sched/smt.h>
#include <linux/sched/stat.h>
#include <linux/sched/sysctl.h>
#include <linux/sched/task_flags.h>
#include <linux/sched/topology.h>
#endif
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/task.h>

#if 0
#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/bug.h>
#include <linux/capability.h>
#include <linux/cgroup_api.h>
#include <linux/cgroup.h>
#include <linux/cpufreq.h>
#include <linux/cpumask_api.h>
#include <linux/ctype.h>
#include <linux/file.h>
#include <linux/fs_api.h>
#include <linux/hrtimer_api.h>
#include <linux/interrupt.h>
#include <linux/irq_work.h>
#include <linux/jiffies.h>
#include <linux/kref_api.h>
#include <linux/kthread.h>
#include <linux/ktime_api.h>
#include <linux/lockdep_api.h>
#include <linux/lockdep.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/mutex_api.h>
#include <linux/plist.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/profile.h>
#include <linux/psi.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/seqlock.h>
#include <linux/softirq.h>
#include <linux/spinlock_api.h>
#include <linux/static_key.h>
#include <linux/stop_machine.h>
#include <linux/syscalls_api.h>
#include <linux/syscalls.h>
#include <linux/tick.h>
#include <linux/topology.h>
#include <linux/types.h>
#include <linux/u64_stats_sync_api.h>
#include <linux/uaccess.h>
#include <linux/wait_api.h>
#include <linux/wait_bit.h>
#include <linux/workqueue_api.h>
#endif
#include <linux/mm.h>

//#include "../workqueue_internal.h"

//#include <linux/static_key.h>

#if 0
#include "cpupri.h"
#include "cpudeadline.h"
#endif

DECLARE_PER_CPU_SHARED_ALIGNED(struct rq, runqueues);

#define cpu_rq(cpu)     (&per_cpu(runqueues, (cpu)))
#define this_rq()       this_cpu_ptr(&runqueues)

/*
 * This is the main, per-CPU runqueue data structure.
 *
 * Locking rule: those places that want to lock multiple runqueues
 * (such as the load balancing or the thread migration code), lock
 * acquire operations must be ordered by ascending &runqueue.
 */
struct rq {
    /* runqueue lock: */
    raw_spinlock_t      __lock;

    /*
     * nr_running and cpu_load should be in the same cacheline because
     * remote CPUs use both these fields when doing load calculation.
     */
    unsigned int        nr_running;

    u64                 nr_switches;

    struct mm_struct    *prev_mm;
};

#endif /* _KERNEL_SCHED_SCHED_H */

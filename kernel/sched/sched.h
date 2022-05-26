/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Scheduler internal types and methods:
 */
#include <linux/sched.h>

/*
#include <linux/sched/autogroup.h>
#include <linux/sched/clock.h>
#include <linux/sched/coredump.h>
#include <linux/sched/cpufreq.h>
#include <linux/sched/cputime.h>
#include <linux/sched/deadline.h>
*/
#include <linux/sched/debug.h>
/*
#include <linux/sched/hotplug.h>
#include <linux/sched/idle.h>
#include <linux/sched/init.h>
#include <linux/sched/isolation.h>
#include <linux/sched/jobctl.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/mm.h>
#include <linux/sched/nohz.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/prio.h>
#include <linux/sched/rt.h>
*/
#include <linux/sched/signal.h>
/*
#include <linux/sched/smt.h>
#include <linux/sched/stat.h>
#include <linux/sched/sysctl.h>
*/
#include <linux/sched/task.h>
//#include <linux/sched/task_stack.h>
//#include <linux/sched/topology.h>
#include <linux/sched/wake_q.h>
/*
#include <linux/sched/user.h>
#include <linux/sched/xacct.h>

#include <uapi/linux/sched/types.h>

#include <linux/binfmts.h>
*/
#include <linux/bitops.h>
#include <linux/compat.h>
/*
#include <linux/context_tracking.h>
#include <linux/cpufreq.h>
#include <linux/cpuidle.h>
#include <linux/cpuset.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/delayacct.h>
#include <linux/energy_model.h>
*/
#include <linux/init_task.h>
/*
#include <linux/kprobes.h>
#include <linux/kthread.h>
#include <linux/membarrier.h>
#include <linux/migrate.h>
#include <linux/mmu_context.h>
#include <linux/nmi.h>
#include <linux/proc_fs.h>
#include <linux/prefetch.h>
#include <linux/profile.h>
#include <linux/psi.h>
#include <linux/ratelimit.h>
#include <linux/rcupdate_wait.h>
#include <linux/security.h>
#include <linux/stop_machine.h>
#include <linux/suspend.h>
#include <linux/swait.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/tsacct_kern.h>
*/

//#include <asm/tlb.h>

/*
#include "cpupri.h"
#include "cpudeadline.h"

#include <trace/events/sched.h>
*/

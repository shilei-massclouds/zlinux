// SPDX-License-Identifier: GPL-2.0-only
/*
 * These are various utility functions of the scheduler,
 * built in a single compilation unit for build efficiency reasons.
 *
 * ( Incidentally, the size of the compilation unit is roughly
 *   comparable to core.c, fair.c, smp.c and policy.c, the other
 *   big compilation units. This helps balance build time, while
 *   coalescing source files to amortize header inclusion
 *   cost. )
 */

#include <linux/sched/mm.h>
#include <linux/sched/debug.h>
#include <linux/sched/isolation.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/clock.h>
#include <linux/cpuset.h>
#include <linux/sched/cputime.h>
#if 0
#include <linux/cpufreq.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/rseq_api.h>

#include <linux/cpumask_api.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/energy_model.h>
#include <linux/hashtable_api.h>
#include <linux/irq.h>
#include <linux/kobject_api.h>
#include <linux/membarrier.h>
#include <linux/mempolicy.h>
#include <linux/nmi.h>
#include <linux/nospec.h>
#include <linux/proc_fs.h>
#include <linux/psi.h>
#include <linux/ptrace_api.h>
#include <linux/sched_clock.h>
#include <linux/security.h>
#include <linux/timex.h>
#include <linux/utsname.h>
#include <linux/wait_api.h>
#include <linux/workqueue_api.h>

#include <uapi/linux/prctl.h>

#include <asm/switch_to.h>
#endif
#include <uapi/linux/sched/types.h>

#include <linux/swait_api.h>
#include <linux/spinlock_api.h>
#include <linux/hash.h>

#include "sched.h"
#if 0
#include "sched-pelt.h"
#include "autogroup.h"

#endif
#include "stats.h"

#include "clock.c"

#include "loadavg.c"
#include "completion.c"
#include "swait.c"
#include "wait_bit.c"
#include "wait.c"

#include "cpupri.c"
#include "stop_task.c"
#include "topology.c"

#include "membarrier.c"

#include "isolation.c"

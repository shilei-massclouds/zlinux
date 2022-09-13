// SPDX-License-Identifier: GPL-2.0-only
/*
 * These are the scheduling policy related scheduler files, built
 * in a single compilation unit for build efficiency reasons.
 *
 * ( Incidentally, the size of the compilation unit is roughly
 *   comparable to core.c and fair.c, the other two big
 *   compilation units. This helps balance build time, while
 *   coalescing source files to amortize header inclusion
 *   cost. )
 *
 * core.c and fair.c are built separately.
 */

/* Headers: */
#if 0
#include <linux/sched/clock.h>
#include <linux/sched/cputime.h>
#include <linux/sched/posix-timers.h>
#endif
#include <linux/sched/rt.h>

#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/cpuidle.h>
#if 0
#include <linux/livepatch.h>
#include <linux/psi.h>
#include <linux/seqlock_api.h>
#include <linux/suspend.h>
#include <linux/tsacct_kern.h>
#include <linux/vtime.h>
#endif

#include <uapi/linux/sched/types.h>

#include "sched.h"

#if 0
#include "autogroup.h"
#include "stats.h"
#endif
#include "pelt.h"

/* Source code modules: */

#include "idle.c"

#include "rt.c"

#include "cpudeadline.c"
#include "pelt.c"

#include "deadline.c"

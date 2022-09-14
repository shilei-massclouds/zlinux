/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Read-Copy Update mechanism for mutual exclusion (tree-based version)
 * Internal non-public definitions that provide either classic
 * or preemptible semantics.
 *
 * Copyright Red Hat, 2009
 * Copyright IBM Corporation, 2009
 *
 * Author: Ingo Molnar <mingo@elte.hu>
 *     Paul E. McKenney <paulmck@linux.ibm.com>
 */

#include "../locking/rtmutex_common.h"

/*
 * Because preemptible RCU does not exist, there are never any preempted
 * RCU readers.
 */
static int rcu_preempt_blocked_readers_cgp(struct rcu_node *rnp)
{
    return 0;
}

/*
 * Because there is no preemptible RCU, there can be no readers blocked.
 */
static bool rcu_preempt_has_tasks(struct rcu_node *rnp)
{
    return false;
}

/*
 * Because there is no preemptible RCU, there can be no deferred quiescent
 * states.
 */
static bool rcu_preempt_need_deferred_qs(struct task_struct *t)
{
    return false;
}

// Except that we do need to respond to a request by an expedited grace
// period for a quiescent state from this CPU.  Note that requests from
// tasks are handled when removing the task from the blocked-tasks list
// below.
static void rcu_preempt_deferred_qs(struct task_struct *t)
{
    struct rcu_data *rdp = this_cpu_ptr(&rcu_data);

#if 0
    if (rdp->cpu_no_qs.b.exp)
        rcu_report_exp_rdp(rdp);
#endif
}

/* Record the current task on dyntick-idle entry. */
static __always_inline void rcu_dynticks_task_enter(void)
{
}

/* Record no current task on dyntick-idle exit. */
static __always_inline void rcu_dynticks_task_exit(void)
{
}

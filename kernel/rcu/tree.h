/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Read-Copy Update mechanism for mutual exclusion (tree-based version)
 * Internal non-public definitions.
 *
 * Copyright IBM Corporation, 2008
 *
 * Author: Ingo Molnar <mingo@elte.hu>
 *     Paul E. McKenney <paulmck@linux.ibm.com>
 */

#include <linux/cache.h>
#include <linux/spinlock.h>
/*
#include <linux/rtmutex.h>
#include <linux/threads.h>
*/
#include <linux/cpumask.h>
/*
#include <linux/seqlock.h>
#include <linux/swait.h>
#include <linux/rcu_node_tree.h>
*/
#include <linux/irq_work.h>
#include <linux/workqueue.h>

#include "rcu_segcblist.h"

/*
 * Union to allow "aggregate OR" operation on the need for a quiescent
 * state by the normal and expedited grace periods.
 */
union rcu_noqs {
    struct {
        u8 norm;
        u8 exp;
    } b; /* Bits. */
    u16 s; /* Set of bits, aggregate OR here. */
};

/* Per-CPU data for read-copy update. */
struct rcu_data {
    /* 1) quiescent-state and grace-period handling : */
    unsigned long   gp_seq;     /* Track rsp->gp_seq counter. */
    unsigned long   gp_seq_needed;  /* Track furthest future GP request. */
    union rcu_noqs  cpu_no_qs;  /* No QSes yet for this CPU. */
    bool        core_needs_qs;  /* Core waits for quiescent state. */
    bool        beenonline; /* CPU online at least once. */
    bool        gpwrap;     /* Possible ->gp_seq wrap. */
    bool        cpu_started;    /* RCU watching this onlining CPU. */
    struct rcu_node *mynode;    /* This CPU's leaf of hierarchy */
    unsigned long grpmask;      /* Mask to apply to leaf qsmask. */
    unsigned long   ticks_this_gp;  /* The number of scheduling-clock */
                    /*  ticks this CPU has handled */
                    /*  during and after the last grace */
                    /* period it is aware of. */
    struct irq_work defer_qs_iw;    /* Obtain later scheduler attention. */
    bool defer_qs_iw_pending;   /* Scheduler attention pending? */
    struct work_struct strict_work; /* Schedule readers for strict GPs. */

    /* 2) batch handling */
    struct rcu_segcblist cblist;    /* Segmented callback list, with */
                    /* different callbacks waiting for */
                    /* different grace periods. */
    long        qlen_last_fqs_check;
                    /* qlen at last check for QS forcing */
    unsigned long   n_cbs_invoked;  /* # callbacks invoked since boot. */
    unsigned long   n_force_qs_snap;
                    /* did other CPU force QS recently? */
    long        blimit;     /* Upper limit on a processed batch */

    /* 3) dynticks interface. */
    int dynticks_snap;      /* Per-GP tracking for dynticks. */
    long dynticks_nesting;      /* Track process nesting level. */
    long dynticks_nmi_nesting;  /* Track irq/NMI nesting level. */
    atomic_t dynticks;      /* Even value for idle, else odd. */
    bool rcu_need_heavy_qs;     /* GP old, so heavy quiescent state! */
    bool rcu_urgent_qs;     /* GP old need light quiescent state. */
    bool rcu_forced_tick;       /* Forced tick to provide QS. */
    bool rcu_forced_tick_exp;   /*   ... provide QS to expedited GP. */

    /* 4) rcu_barrier(), OOM callbacks, and expediting. */
    unsigned long barrier_seq_snap; /* Snap of rcu_state.barrier_sequence. */
    struct rcu_head barrier_head;
    int exp_dynticks_snap;      /* Double-check need for IPI. */

    /* 5) Callback offloading. */

    /* 6) RCU priority boosting. */
    struct task_struct *rcu_cpu_kthread_task;
                    /* rcuc per-CPU kthread or NULL. */
    unsigned int rcu_cpu_kthread_status;
    char rcu_cpu_has_work;
    unsigned long rcuc_activity;

    /* 7) Diagnostic data, including RCU CPU stall warnings. */
    unsigned int softirq_snap;  /* Snapshot of softirq activity. */
    /* ->rcu_iw* fields protected by leaf rcu_node ->lock. */
    struct irq_work rcu_iw;     /* Check for non-irq activity. */
    bool rcu_iw_pending;        /* Is ->rcu_iw pending? */
    unsigned long rcu_iw_gp_seq;    /* ->gp_seq associated with ->rcu_iw. */
    unsigned long rcu_ofl_gp_seq;   /* ->gp_seq at last offline. */
    short rcu_ofl_gp_flags;     /* ->gp_flags at last offline. */
    unsigned long rcu_onl_gp_seq;   /* ->gp_seq at last online. */
    short rcu_onl_gp_flags;     /* ->gp_flags at last online. */
    unsigned long last_fqs_resched; /* Time of last rcu_resched(). */

    int cpu;
};

static void rcu_preempt_deferred_qs(struct task_struct *t);

static void rcu_bind_gp_kthread(void);
static bool rcu_nohz_full_cpu(void);
static void rcu_dynticks_task_enter(void);
static void rcu_dynticks_task_exit(void);
static void rcu_dynticks_task_trace_enter(void);
static void rcu_dynticks_task_trace_exit(void);

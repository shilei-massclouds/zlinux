/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Sleepable Read-Copy Update mechanism for mutual exclusion,
 *  tree variant.
 *
 * Copyright (C) IBM Corporation, 2017
 *
 * Author: Paul McKenney <paulmck@linux.ibm.com>
 */

#ifndef _LINUX_SRCU_TREE_H
#define _LINUX_SRCU_TREE_H

#if 0
#include <linux/rcu_node_tree.h>
#endif
#include <linux/completion.h>

struct srcu_node;
struct srcu_struct;

/*
 * Per-SRCU-domain structure, similar in function to rcu_state.
 */
struct srcu_struct {
#if 0
    struct srcu_node node[NUM_RCU_NODES];   /* Combining tree. */
    struct srcu_node *level[RCU_NUM_LVLS + 1];
                        /* First node at each level. */
    struct mutex srcu_cb_mutex;     /* Serialize CB preparation. */
    spinlock_t __private lock;      /* Protect counters */
    struct mutex srcu_gp_mutex;     /* Serialize GP work. */
    unsigned int srcu_idx;          /* Current rdr array element. */
    unsigned long srcu_gp_seq;      /* Grace-period seq #. */
    unsigned long srcu_gp_seq_needed;   /* Latest gp_seq needed. */
    unsigned long srcu_gp_seq_needed_exp;   /* Furthest future exp GP. */
    unsigned long srcu_last_gp_end;     /* Last GP end timestamp (ns) */
    struct srcu_data __percpu *sda;     /* Per-CPU srcu_data array. */
    unsigned long srcu_barrier_seq;     /* srcu_barrier seq #. */
    struct mutex srcu_barrier_mutex;    /* Serialize barrier ops. */
    struct completion srcu_barrier_completion;
                        /* Awaken barrier rq at end. */
    atomic_t srcu_barrier_cpu_cnt;      /* # CPUs not yet posting a */
                        /*  callback for the barrier */
                        /*  operation. */
    struct delayed_work work;
    struct lockdep_map dep_map;
#endif
};

#endif /* _LINUX_SRCU_TREE_H */

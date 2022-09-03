/* SPDX-License-Identifier: GPL-2.0 */
/*
 * linux/cgroup-defs.h - basic definitions for cgroup
 *
 * This file provides basic type and interface.  Include this file directly
 * only if necessary to avoid cyclic dependencies.
 */
#ifndef _LINUX_CGROUP_DEFS_H
#define _LINUX_CGROUP_DEFS_H

#include <linux/limits.h>
#include <linux/list.h>
#include <linux/idr.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/percpu-refcount.h>
#include <linux/percpu-rwsem.h>
//#include <linux/u64_stats_sync.h>
#include <linux/workqueue.h>
#if 0
#include <linux/bpf-cgroup-defs.h>
#include <linux/psi_types.h>
#endif

/*
 * Per-subsystem/per-cgroup state maintained by the system.  This is the
 * fundamental structural building block that controllers deal with.
 *
 * Fields marked with "PI:" are public and immutable and may be accessed
 * directly without synchronization.
 */
struct cgroup_subsys_state {
    /* PI: the cgroup that this css is attached to */
    struct cgroup *cgroup;

    /* PI: the cgroup subsystem that this css is attached to */
    struct cgroup_subsys *ss;

    /* reference count - access via css_[try]get() and css_put() */
    struct percpu_ref refcnt;

    /* siblings list anchored at the parent's ->children */
    struct list_head sibling;
    struct list_head children;

    /* flush target list anchored at cgrp->rstat_css_list */
    struct list_head rstat_css_node;

    /*
     * PI: Subsys-unique ID.  0 is unused and root is always 1.  The
     * matching css can be looked up using css_from_id().
     */
    int id;

    unsigned int flags;

    /*
     * Monotonically increasing unique serial number which defines a
     * uniform order among all csses.  It's guaranteed that all
     * ->children lists are in the ascending order of ->serial_nr and
     * used to allow interrupting and resuming iterations.
     */
    u64 serial_nr;

    /*
     * Incremented by online self and children.  Used to guarantee that
     * parents are not offlined before their children.
     */
    atomic_t online_cnt;

    /* percpu_ref killing and RCU release */
    struct work_struct destroy_work;
    struct rcu_work destroy_rwork;

    /*
     * PI: the parent css.  Placed here for cache proximity to following
     * fields of the containing structure.
     */
    struct cgroup_subsys_state *parent;
};

#endif  /* _LINUX_CGROUP_DEFS_H */

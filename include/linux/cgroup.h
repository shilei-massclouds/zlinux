/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_CGROUP_H
#define _LINUX_CGROUP_H
/*
 *  cgroup interface
 *
 *  Copyright (C) 2003 BULL SA
 *  Copyright (C) 2004-2006 Silicon Graphics, Inc.
 *
 */

#include <linux/sched.h>
#include <linux/cpumask.h>
#include <linux/nodemask.h>
#include <linux/rculist.h>
//#include <linux/cgroupstats.h>
#include <linux/fs.h>
//#include <linux/seq_file.h>
//#include <linux/kernfs.h>
#include <linux/jump_label.h>
#include <linux/types.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/user_namespace.h>
#include <linux/refcount.h>
#include <linux/kernel_stat.h>

#include <linux/cgroup-defs.h>

struct kernel_clone_args;

static inline void cgroup_init_kthreadd(void)
{
    /*
     * kthreadd is inherited by all kthreads, keep it in the root so
     * that the new kthreads are guaranteed to stay in the root until
     * initialization is finished.
     */
    current->no_cgroup_migration = 1;
}

static inline void cgroup_kthread_ready(void)
{
    /*
     * This kthread finished initialization.  The creator should have
     * set PF_NO_SETAFFINITY if this kthread should stay in the root.
     */
    current->no_cgroup_migration = 0;
}

#endif /* _LINUX_CGROUP_H */

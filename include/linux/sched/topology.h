/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_TOPOLOGY_H
#define _LINUX_SCHED_TOPOLOGY_H

#include <linux/topology.h>

//#include <linux/sched/idle.h>

struct sched_domain {
    /* These fields must be setup */
    struct sched_domain __rcu *parent;  /* top domain must be null terminated */
    struct sched_domain __rcu *child;   /* bottom domain must be null terminated */

    int flags;  /* See SD_* */
};

#endif /* _LINUX_SCHED_TOPOLOGY_H */

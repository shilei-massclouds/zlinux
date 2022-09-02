/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_TOPOLOGY_H
#define _LINUX_SCHED_TOPOLOGY_H

#include <linux/topology.h>

#include <linux/sched/idle.h>

struct sched_domain {
    /* These fields must be setup */
    struct sched_domain __rcu *parent;  /* top domain must be null terminated */
    struct sched_domain __rcu *child;   /* bottom domain must be null terminated */

    int flags;  /* See SD_* */
};

bool cpus_share_cache(int this_cpu, int that_cpu);

#ifndef arch_scale_cpu_capacity
/**
 * arch_scale_cpu_capacity - get the capacity scale factor of a given CPU.
 * @cpu: the CPU in question.
 *
 * Return: the CPU scale factor normalized against SCHED_CAPACITY_SCALE, i.e.
 *
 *             max_perf(cpu)
 *      ----------------------------- * SCHED_CAPACITY_SCALE
 *      max(max_perf(c) : c \in CPUs)
 */
static __always_inline
unsigned long arch_scale_cpu_capacity(int cpu)
{
    return SCHED_CAPACITY_SCALE;
}
#endif

#endif /* _LINUX_SCHED_TOPOLOGY_H */

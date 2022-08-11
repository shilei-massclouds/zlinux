/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_STOP_MACHINE
#define _LINUX_STOP_MACHINE

#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/smp.h>
#include <linux/list.h>

/*
 * stop_cpu[s]() is simplistic per-cpu maximum priority cpu
 * monopolization mechanism.  The caller can specify a non-sleeping
 * function to be executed on a single or multiple cpus preempting all
 * other processes and monopolizing those cpus until it finishes.
 *
 * Resources for this mechanism are preallocated when a cpu is brought
 * up and requests are guaranteed to be served as long as the target
 * cpus are online.
 */
typedef int (*cpu_stop_fn_t)(void *arg);

struct cpu_stop_work {
    struct list_head    list;       /* cpu_stopper->works */
    cpu_stop_fn_t       fn;
    unsigned long       caller;
    void                *arg;
    struct cpu_stop_done    *done;
};

int stop_one_cpu(unsigned int cpu, cpu_stop_fn_t fn, void *arg);

#endif  /* _LINUX_STOP_MACHINE */

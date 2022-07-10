// SPDX-License-Identifier: GPL-2.0-only
/* Kernel thread helper functions.
 *   Copyright (C) 2004 IBM Corporation, Rusty Russell.
 *   Copyright (C) 2009 Red Hat, Inc.
 *
 * Creation is done via kthreadd, so that we get a clean environment
 * even if we're invoked from userspace (think modprobe, hotplug cpu,
 * etc.).
 */
//#include <uapi/linux/sched/types.h>
#include <linux/mm.h>
//#include <linux/mmu_context.h>
#include <linux/sched.h>
//#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/err.h>
//#include <linux/cgroup.h>
//#include <linux/cpuset.h>
//#include <linux/unistd.h>
//#include <linux/file.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/slab.h>
//#include <linux/freezer.h>
//#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/numa.h>
//#include <linux/sched/isolation.h>

struct kthread {
    unsigned long flags;
    unsigned int cpu;
    int result;
    int (*threadfn)(void *);
    void *data;
    struct completion parked;
    struct completion exited;
    /* To store the full name if task comm is truncated. */
    char *full_name;
};

/* called from do_fork() to get node information for about to be created task */
int tsk_fork_get_node(struct task_struct *tsk)
{
    return NUMA_NO_NODE;
}

static inline struct kthread *to_kthread(struct task_struct *k)
{
    WARN_ON(!(k->flags & PF_KTHREAD));
    return k->worker_private;
}

bool set_kthread_struct(struct task_struct *p)
{
    struct kthread *kthread;

    if (WARN_ON_ONCE(to_kthread(p)))
        return false;

    kthread = kzalloc(sizeof(*kthread), GFP_KERNEL);
    if (!kthread)
        return false;

    init_completion(&kthread->exited);
    init_completion(&kthread->parked);
    p->vfork_done = &kthread->exited;

    p->worker_private = kthread;
    return true;
}

/**
 * kthread_stop - stop a thread created by kthread_create().
 * @k: thread created by kthread_create().
 *
 * Sets kthread_should_stop() for @k to return true, wakes it, and
 * waits for it to exit. This can also be called after kthread_create()
 * instead of calling wake_up_process(): the thread will exit without
 * calling threadfn().
 *
 * If threadfn() may call kthread_exit() itself, the caller must ensure
 * task_struct can't go away.
 *
 * Returns the result of threadfn(), or %-EINTR if wake_up_process()
 * was never called.
 */
int kthread_stop(struct task_struct *k)
{
#if 0
    struct kthread *kthread;
    int ret;

    get_task_struct(k);
    kthread = to_kthread(k);
    set_bit(KTHREAD_SHOULD_STOP, &kthread->flags);
    kthread_unpark(k);
    wake_up_process(k);
    wait_for_completion(&kthread->exited);
    ret = kthread->result;
    put_task_struct(k);

    return ret;
#endif
    panic("%s: END!\n", __func__);
}

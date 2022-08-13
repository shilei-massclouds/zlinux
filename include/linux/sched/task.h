/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_TASK_H
#define _LINUX_SCHED_TASK_H

#include <linux/sched.h>
#include <linux/uaccess.h>

#define arch_task_struct_size (sizeof(struct task_struct))

extern rwlock_t tasklist_lock;

extern struct task_struct init_task;

extern pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags);

struct kernel_clone_args {
    u64 flags;
    int __user *pidfd;
    int __user *child_tid;
    int __user *parent_tid;
    int exit_signal;
    unsigned long stack;
    unsigned long stack_size;
    unsigned long tls;
    pid_t *set_tid;
    /* Number of elements in *set_tid */
    size_t set_tid_size;
    int cgroup;
    int io_thread;
    struct cgroup *cgrp;
    struct css_set *cset;
};

static inline struct task_struct *get_task_struct(struct task_struct *t)
{
    refcount_inc(&t->usage);
    return t;
}

extern void __put_task_struct(struct task_struct *t);

static inline void put_task_struct(struct task_struct *t)
{
    if (refcount_dec_and_test(&t->usage))
        __put_task_struct(t);
}

extern void fork_init(void);

extern int sched_fork(unsigned long clone_flags, struct task_struct *p);

extern int copy_thread(unsigned long, unsigned long, unsigned long,
                       struct task_struct *, unsigned long);

static inline struct vm_struct *task_stack_vm_area(const struct task_struct *t)
{
    return t->stack_vm_area;
}

extern asmlinkage void schedule_tail(struct task_struct *prev);

void put_task_struct_rcu_user(struct task_struct *task);

extern void proc_caches_init(void);

/*
 * Protects ->fs, ->files, ->mm, ->group_info, ->comm, keyring
 * subscriptions and synchronises with wait4().  Also used in procfs.  Also
 * pins the final release of task.io_context.  Also protects ->cpuset and
 * ->cgroup.subsys[]. And ->vfork_done. And ->sysvshm.shm_clist.
 *
 * Nests both inside and outside of read_lock(&tasklist_lock).
 * It must not be nested with write_lock_irq(&tasklist_lock),
 * neither inside nor outside.
 */
static inline void task_lock(struct task_struct *p)
{
    spin_lock(&p->alloc_lock);
}

static inline void task_unlock(struct task_struct *p)
{
    spin_unlock(&p->alloc_lock);
}

extern void sched_exec(void);

extern void flush_thread(void);

#endif /* _LINUX_SCHED_TASK_H */

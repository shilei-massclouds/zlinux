/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PID_H
#define _LINUX_PID_H

#include <linux/rculist.h>
#include <linux/wait.h>
#include <linux/refcount.h>

struct pid_namespace;

enum pid_type
{
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};

/*
 * What is struct pid?
 *
 * A struct pid is the kernel's internal notion of a process identifier.
 * It refers to individual tasks, process groups, and sessions.  While
 * there are processes attached to it the struct pid lives in a hash
 * table, so it and then the processes that it refers to can be found
 * quickly from the numeric pid value.  The attached processes may be
 * quickly accessed by following pointers from struct pid.
 *
 * Storing pid_t values in the kernel and referring to them later has a
 * problem.  The process originally with that pid may have exited and the
 * pid allocator wrapped, and another process could have come along
 * and been assigned that pid.
 *
 * Referring to user space processes by holding a reference to struct
 * task_struct has a problem.  When the user space process exits
 * the now useless task_struct is still kept.  A task_struct plus a
 * stack consumes around 10K of low kernel memory.  More precisely
 * this is THREAD_SIZE + sizeof(struct task_struct).  By comparison
 * a struct pid is about 64 bytes.
 *
 * Holding a reference to struct pid solves both of these problems.
 * It is small so holding a reference does not consume a lot of
 * resources, and since a new struct pid is allocated when the numeric pid
 * value is reused (when pids wrap around) we don't mistakenly refer to new
 * processes.
 */

/*
 * struct upid is used to get the id of the struct pid, as it is
 * seen in particular namespace. Later the struct pid is found with
 * find_pid_ns() using the int nr and struct pid_namespace *ns.
 */

struct upid {
    int nr;
    struct pid_namespace *ns;
};

struct pid
{
    refcount_t count;
    unsigned int level;
#if 0
    spinlock_t lock;
    /* lists of tasks that use this pid */
    struct hlist_head tasks[PIDTYPE_MAX];
    struct hlist_head inodes;
    /* wait queue for pidfd notifications */
    wait_queue_head_t wait_pidfd;
    struct rcu_head rcu;
#endif
    struct upid numbers[1];
};

extern struct pid *get_task_pid(struct task_struct *task, enum pid_type type);

/*
 * the helpers to get the pid's id seen from different namespaces
 *
 * pid_nr()    : global id, i.e. the id seen from the init namespace;
 * pid_vnr()   : virtual id, i.e. the id seen from the pid namespace of
 *               current.
 * pid_nr_ns() : id seen from the ns specified.
 *
 * see also task_xid_nr() etc in include/linux/sched.h
 */

static inline pid_t pid_nr(struct pid *pid)
{
    pid_t nr = 0;
    if (pid)
        nr = pid->numbers[0].nr;
    return nr;
}

pid_t pid_nr_ns(struct pid *pid, struct pid_namespace *ns);
pid_t pid_vnr(struct pid *pid);

extern struct pid init_struct_pid;

static inline struct pid *get_pid(struct pid *pid)
{
    if (pid)
        refcount_inc(&pid->count);
    return pid;
}

/*
 * ns_of_pid() returns the pid namespace in which the specified pid was
 * allocated.
 *
 * NOTE:
 *  ns_of_pid() is expected to be called for a process (task) that has
 *  an attached 'struct pid' (see attach_pid(), detach_pid()) i.e @pid
 *  is expected to be non-NULL. If @pid is NULL, caller should handle
 *  the resulting NULL pid-ns.
 */
static inline struct pid_namespace *ns_of_pid(struct pid *pid)
{
    struct pid_namespace *ns = NULL;
    if (pid)
        ns = pid->numbers[pid->level].ns;
    return ns;
}

extern struct pid *
alloc_pid(struct pid_namespace *ns, pid_t *set_tid, size_t set_tid_size);

#endif /* _LINUX_PID_H */

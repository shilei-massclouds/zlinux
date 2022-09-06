// SPDX-License-Identifier: GPL-2.0-only
/* Kernel thread helper functions.
 *   Copyright (C) 2004 IBM Corporation, Rusty Russell.
 *   Copyright (C) 2009 Red Hat, Inc.
 *
 * Creation is done via kthreadd, so that we get a clean environment
 * even if we're invoked from userspace (think modprobe, hotplug cpu,
 * etc.).
 */
#include <uapi/linux/sched/types.h>
#include <linux/mm.h>
//#include <linux/mmu_context.h>
#include <linux/sched.h>
//#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/cgroup.h>
#include <linux/cpuset.h>
//#include <linux/unistd.h>
//#include <linux/file.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/slab.h>
//#include <linux/freezer.h>
//#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/numa.h>
#include <linux/sched/isolation.h>

static DEFINE_SPINLOCK(kthread_create_lock);
static LIST_HEAD(kthread_create_list);
struct task_struct *kthreadd_task;

enum KTHREAD_BITS {
    KTHREAD_IS_PER_CPU = 0,
    KTHREAD_SHOULD_STOP,
    KTHREAD_SHOULD_PARK,
};

struct kthread_create_info
{
    /* Information passed to kthread() from kthreadd. */
    int (*threadfn)(void *data);
    void *data;
    int node;

    /* Result passed back to kthread_create() from kthreadd. */
    struct task_struct *result;
    struct completion *done;

    struct list_head list;
};

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

static __printf(4, 0)
struct task_struct *__kthread_create_on_node(int (*threadfn)(void *data),
                                             void *data, int node,
                                             const char namefmt[],
                                             va_list args)
{
    DECLARE_COMPLETION_ONSTACK(done);
    struct task_struct *task;
    struct kthread_create_info *create = kmalloc(sizeof(*create), GFP_KERNEL);
    if (!create)
        return ERR_PTR(-ENOMEM);

    create->threadfn = threadfn;
    create->data = data;
    create->node = node;
    create->done = &done;

    spin_lock(&kthread_create_lock);
    list_add_tail(&create->list, &kthread_create_list);
    spin_unlock(&kthread_create_lock);

    wake_up_process(kthreadd_task);
    /*
     * Wait for completion in killable state, for I might be chosen by
     * the OOM killer while kthreadd is trying to allocate memory for
     * new kernel thread.
     */
    if (unlikely(wait_for_completion_killable(&done))) {
        panic("%s: 1!\n", __func__);
    }

    panic("%s: END!\n", __func__);
}

/**
 * kthread_create_on_node - create a kthread.
 * @threadfn: the function to run until signal_pending(current).
 * @data: data ptr for @threadfn.
 * @node: task and thread structures for the thread are allocated on this node
 * @namefmt: printf-style name for the thread.
 *
 * Description: This helper function creates and names a kernel
 * thread.  The thread will be stopped: use wake_up_process() to start
 * it.  See also kthread_run().  The new thread has SCHED_NORMAL policy and
 * is affine to all CPUs.
 *
 * If thread is going to be bound on a particular cpu, give its node
 * in @node, to get NUMA affinity for kthread stack, or else give NUMA_NO_NODE.
 * When woken, the thread will run @threadfn() with @data as its
 * argument. @threadfn() can either return directly if it is a
 * standalone thread for which no one will call kthread_stop(), or
 * return when 'kthread_should_stop()' is true (which means
 * kthread_stop() has been called).  The return value should be zero
 * or a negative error number; it will be passed to kthread_stop().
 *
 * Returns a task_struct or ERR_PTR(-ENOMEM) or ERR_PTR(-EINTR).
 */
struct task_struct *kthread_create_on_node(int (*threadfn)(void *data),
                       void *data, int node,
                       const char namefmt[],
                       ...)
{
    struct task_struct *task;
    va_list args;

    va_start(args, namefmt);
    task = __kthread_create_on_node(threadfn, data, node, namefmt, args);
    va_end(args);

    return task;
}
EXPORT_SYMBOL(kthread_create_on_node);

static void __kthread_bind_mask(struct task_struct *p,
                                const struct cpumask *mask,
                                unsigned int state)
{
    unsigned long flags;

    if (!wait_task_inactive(p, state)) {
        WARN_ON(1);
        return;
    }

    /* It's safe because the task is inactive. */
    raw_spin_lock_irqsave(&p->pi_lock, flags);
    do_set_cpus_allowed(p, mask);
    p->flags |= PF_NO_SETAFFINITY;
    raw_spin_unlock_irqrestore(&p->pi_lock, flags);
}

static void __kthread_bind(struct task_struct *p,
                           unsigned int cpu,
                           unsigned int state)
{
    __kthread_bind_mask(p, cpumask_of(cpu), state);
}

/**
 * kthread_bind - bind a just-created kthread to a cpu.
 * @p: thread created by kthread_create().
 * @cpu: cpu (might not be online, must be possible) for @k to run on.
 *
 * Description: This function is equivalent to set_cpus_allowed(),
 * except that @cpu doesn't need to be online, and the thread must be
 * stopped (i.e., just returned from kthread_create()).
 */
void kthread_bind(struct task_struct *p, unsigned int cpu)
{
    __kthread_bind(p, cpu, TASK_UNINTERRUPTIBLE);
}
EXPORT_SYMBOL(kthread_bind);

/**
 * kthread_create_on_cpu - Create a cpu bound kthread
 * @threadfn: the function to run until signal_pending(current).
 * @data: data ptr for @threadfn.
 * @cpu: The cpu on which the thread should be bound,
 * @namefmt: printf-style name for the thread. Format is restricted
 *       to "name.*%u". Code fills in cpu number.
 *
 * Description: This helper function creates and names a kernel thread
 */
struct task_struct *kthread_create_on_cpu(int (*threadfn)(void *data),
                      void *data, unsigned int cpu,
                      const char *namefmt)
{
    struct task_struct *p;

    p = kthread_create_on_node(threadfn, data, cpu_to_node(cpu), namefmt, cpu);
    if (IS_ERR(p))
        return p;
    kthread_bind(p, cpu);
    /* CPU hotplug need to bind once again when unparking the thread. */
    to_kthread(p)->cpu = cpu;
    return p;
}
EXPORT_SYMBOL(kthread_create_on_cpu);

bool __kthread_should_park(struct task_struct *k)
{
    return test_bit(KTHREAD_SHOULD_PARK, &to_kthread(k)->flags);
}
EXPORT_SYMBOL_GPL(__kthread_should_park);

void free_kthread_struct(struct task_struct *k)
{
    struct kthread *kthread;

    /*
     * Can be NULL if kmalloc() in set_kthread_struct() failed.
     */
    kthread = to_kthread(k);
    if (!kthread)
        return;

    k->worker_private = NULL;
    kfree(kthread->full_name);
    kfree(kthread);
}

/**
 * kthread_unpark - unpark a thread created by kthread_create().
 * @k:      thread created by kthread_create().
 *
 * Sets kthread_should_park() for @k to return false, wakes it, and
 * waits for it to return. If the thread is marked percpu then its
 * bound to the cpu again.
 */
void kthread_unpark(struct task_struct *k)
{
    struct kthread *kthread = to_kthread(k);

    /*
     * Newly created kthread was parked when the CPU was offline.
     * The binding was lost and we need to set it again.
     */
    if (test_bit(KTHREAD_IS_PER_CPU, &kthread->flags))
        __kthread_bind(k, kthread->cpu, TASK_PARKED);

    clear_bit(KTHREAD_SHOULD_PARK, &kthread->flags);
    /*
     * __kthread_parkme() will either see !SHOULD_PARK or get the wakeup.
     */
    wake_up_state(k, TASK_PARKED);
}
EXPORT_SYMBOL_GPL(kthread_unpark);

/**
 * kthread_exit - Cause the current kthread return @result to kthread_stop().
 * @result: The integer value to return to kthread_stop().
 *
 * While kthread_exit can be called directly, it exists so that
 * functions which do some additional work in non-modular code such as
 * module_put_and_kthread_exit can be implemented.
 *
 * Does not return.
 */
void __noreturn kthread_exit(long result)
{
    struct kthread *kthread = to_kthread(current);
    kthread->result = result;
    do_exit(0);
}

static void __kthread_parkme(struct kthread *self)
{
    for (;;) {
        /*
         * TASK_PARKED is a special state; we must serialize against
         * possible pending wakeups to avoid store-store collisions on
         * task->state.
         *
         * Such a collision might possibly result in the task state
         * changin from TASK_PARKED and us failing the
         * wait_task_inactive() in kthread_park().
         */
        set_special_state(TASK_PARKED);
        if (!test_bit(KTHREAD_SHOULD_PARK, &self->flags))
            break;

        /*
         * Thread is going to call schedule(), do not preempt it,
         * or the caller of kthread_park() may spend more time in
         * wait_task_inactive().
         */
        preempt_disable();
        complete(&self->parked);
        schedule_preempt_disabled();
        preempt_enable();
    }
    __set_current_state(TASK_RUNNING);
}

static int kthread(void *_create)
{
    static const struct sched_param param = { .sched_priority = 0 };
    /* Copy data: it's on kthread's stack */
    struct kthread_create_info *create = _create;
    int (*threadfn)(void *data) = create->threadfn;
    void *data = create->data;
    struct completion *done;
    struct kthread *self;
    int ret;

    printk("###### %s: step1\n", __func__);
    self = to_kthread(current);

    /* If user was SIGKILLed, I release the structure. */
    done = xchg(&create->done, NULL);
    if (!done) {
        kfree(create);
        kthread_exit(-EINTR);
    }

    self->threadfn = threadfn;
    self->data = data;

    /*
     * The new thread inherited kthreadd's priority and CPU mask. Reset
     * back to default in case they have been changed.
     */
    sched_setscheduler_nocheck(current, SCHED_NORMAL, &param);
    set_cpus_allowed_ptr(current, housekeeping_cpumask(HK_TYPE_KTHREAD));

    /* OK, tell user we're spawned, wait for stop or wakeup */
    __set_current_state(TASK_UNINTERRUPTIBLE);
    create->result = current;

    /*
     * Thread is going to call schedule(), do not preempt it,
     * or the creator may spend more time in wait_task_inactive().
     */
    preempt_disable();
    complete(done);
    printk("%s: step1\n", __func__);
    schedule_preempt_disabled();
    printk("%s: step2\n", __func__);
    preempt_enable();

    ret = -EINTR;
    if (!test_bit(KTHREAD_SHOULD_STOP, &self->flags)) {
        cgroup_kthread_ready();
        __kthread_parkme(self);
        ret = threadfn(data);
    }
    kthread_exit(ret);
}

static void create_kthread(struct kthread_create_info *create)
{
    int pid;

    /* We want our own signal handler (we take no signals by default). */
    pid = kernel_thread(kthread, create, CLONE_FS | CLONE_FILES | SIGCHLD);
    if (pid < 0) {
        panic("%s: pid < 0 !\n", __func__);
    }
}

int kthreadd(void *unused)
{
    struct task_struct *tsk = current;

    pr_info("################# %s: \n", __func__);
    /* Setup a clean context for our children to inherit. */
    set_task_comm(tsk, "kthreadd");
    //ignore_signals(tsk);
    set_cpus_allowed_ptr(tsk, housekeeping_cpumask(HK_TYPE_KTHREAD));
    set_mems_allowed(node_states[N_MEMORY]);

    current->flags |= PF_NOFREEZE;
    cgroup_init_kthreadd();

    for (;;) {
        set_current_state(TASK_INTERRUPTIBLE);
        if (list_empty(&kthread_create_list))
            schedule();
        __set_current_state(TASK_RUNNING);

        spin_lock(&kthread_create_lock);
        while (!list_empty(&kthread_create_list)) {
            struct kthread_create_info *create;

            create = list_entry(kthread_create_list.next,
                                struct kthread_create_info, list);
            list_del_init(&create->list);
            spin_unlock(&kthread_create_lock);

            pr_info("%s: 1\n", __func__);
            create_kthread(create);

            spin_lock(&kthread_create_lock);
        }
        spin_unlock(&kthread_create_lock);
    }

    return 0;
}

/**
 * kthread_should_stop - should this kthread return now?
 *
 * When someone calls kthread_stop() on your kthread, it will be woken
 * and this will return true.  You should then return, and your return
 * value will be passed through to kthread_stop().
 */
bool kthread_should_stop(void)
{
    return test_bit(KTHREAD_SHOULD_STOP, &to_kthread(current)->flags);
}
EXPORT_SYMBOL(kthread_should_stop);

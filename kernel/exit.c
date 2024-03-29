// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/exit.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/mm.h>
#if 0
#include <linux/sched/stat.h>
#include <linux/sched/cputime.h>
#endif
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#if 0
#include <linux/capability.h>
#endif
#include <linux/completion.h>
#if 0
#include <linux/personality.h>
#include <linux/tty.h>
#include <linux/iocontext.h>
#include <linux/key.h>
#include <linux/cpu.h>
#include <linux/acct.h>
#include <linux/tsacct_kern.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/freezer.h>
#include <linux/binfmts.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/profile.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/cgroup.h>
#include <linux/signal.h>
#include <linux/posix-timers.h>
#include <linux/cn_proc.h>
#include <linux/mutex.h>
#include <linux/futex.h>
#include <linux/pipe_fs_i.h>
#include <linux/audit.h> /* for audit_free() */
#include <linux/resource.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/blkdev.h>
#include <linux/task_work.h>
#include <linux/fs_struct.h>
#include <linux/init_task.h>
#include <linux/perf_event.h>
#include <trace/events/sched.h>
#include <linux/hw_breakpoint.h>
#include <linux/oom.h>
#include <linux/writeback.h>
#include <linux/shm.h>
#include <linux/kcov.h>
#include <linux/random.h>
#include <linux/compat.h>
#include <linux/io_uring.h>
#include <linux/kprobes.h>
#include <linux/rethook.h>

#include <linux/uaccess.h>
#endif
#include <linux/syscalls.h>
#include <linux/rcuwait.h>

#include <asm/unistd.h>
#include <asm/mmu_context.h>

static void delayed_put_task_struct(struct rcu_head *rhp)
{
#if 0
    struct task_struct *tsk = container_of(rhp, struct task_struct, rcu);

    kprobe_flush_task(tsk);
    rethook_flush_task(tsk);
    perf_event_delayed_put(tsk);
    trace_sched_process_free(tsk);
    put_task_struct(tsk);
#endif
    panic("%s: NOT-implemented!\n", __func__);
}

void put_task_struct_rcu_user(struct task_struct *task)
{
    if (refcount_dec_and_test(&task->rcu_users))
        call_rcu(&task->rcu, delayed_put_task_struct);
}

int rcuwait_wake_up(struct rcuwait *w)
{
    int ret = 0;
    struct task_struct *task;

    rcu_read_lock();

    /*
     * Order condition vs @task, such that everything prior to the load
     * of @task is visible. This is the condition as to why the user called
     * rcuwait_wake() in the first place. Pairs with set_current_state()
     * barrier (A) in rcuwait_wait_event().
     *
     *    WAIT                WAKE
     *    [S] tsk = current   [S] cond = true
     *        MB (A)          MB (B)
     *    [L] cond        [L] tsk
     */
    smp_mb(); /* (B) */

    task = rcu_dereference(w->task);
    if (task)
        ret = wake_up_process(task);
    rcu_read_unlock();

    return ret;
}
EXPORT_SYMBOL_GPL(rcuwait_wake_up);

static void coredump_task_exit(struct task_struct *tsk)
{
    struct core_state *core_state;

    /*
     * Serialize with any possible pending coredump.
     * We must hold siglock around checking core_state
     * and setting PF_POSTCOREDUMP.  The core-inducing thread
     * will increment ->nr_threads for each thread in the
     * group without PF_POSTCOREDUMP set.
     */
    spin_lock_irq(&tsk->sighand->siglock);
    tsk->flags |= PF_POSTCOREDUMP;
    core_state = tsk->signal->core_state;
    spin_unlock_irq(&tsk->sighand->siglock);
    if (core_state) {
        panic("%s: unimplemented!\n", __func__);
    }
}

void __noreturn do_exit(long code)
{
    struct task_struct *tsk = current;
    int group_dead;

    WARN_ON(tsk->plug);

    coredump_task_exit(tsk);
    //ptrace_event(PTRACE_EVENT_EXIT, code);

    validate_creds_for_do_exit(tsk);

    //io_uring_files_cancel();
    exit_signals(tsk);  /* sets PF_EXITING */

    /* sync mm's RSS info before statistics gathering */
    if (tsk->mm)
        sync_mm_rss(tsk->mm);
    group_dead = atomic_dec_and_test(&tsk->signal->live);
    if (group_dead) {
        /*
         * If the last thread of global init has exited, panic
         * immediately to get a useable coredump.
         */
        if (unlikely(is_global_init(tsk)))
            panic("Attempted to kill init! exitcode=0x%08x\n",
                  tsk->signal->group_exit_code ?: (int)code);

        panic("%s: group_dead\n", __func__);
    }
    panic("%s: NOT-implemented code(%ld)!\n", __func__, code);
}

/*
 * Take down every thread in the group.  This is called by fatal signals
 * as well as by sys_exit_group (below).
 */
void __noreturn
do_group_exit(int exit_code)
{
    struct signal_struct *sig = current->signal;

    printk("%s: ...\n", __func__);

    if (sig->flags & SIGNAL_GROUP_EXIT)
        exit_code = sig->group_exit_code;
    else if (sig->group_exec_task)
        exit_code = 0;
    else if (!thread_group_empty(current)) {
        struct sighand_struct *const sighand = current->sighand;

        spin_lock_irq(&sighand->siglock);
        if (sig->flags & SIGNAL_GROUP_EXIT)
            /* Another thread got here before we took the lock.  */
            exit_code = sig->group_exit_code;
        else if (sig->group_exec_task)
            exit_code = 0;
        else {
            sig->group_exit_code = exit_code;
            sig->flags = SIGNAL_GROUP_EXIT;
            zap_other_threads(current);
        }
        spin_unlock_irq(&sighand->siglock);
    }

    do_exit(exit_code);
    /* NOTREACHED */
}

/*
 * this kills every thread in the thread group. Note that any externally
 * wait4()-ing process will get the correct exit code - even if this
 * thread is not the thread group leader.
 */
SYSCALL_DEFINE1(exit_group, int, error_code)
{
    do_group_exit((error_code & 0xff) << 8);
    /* NOTREACHED */
    return 0;
}

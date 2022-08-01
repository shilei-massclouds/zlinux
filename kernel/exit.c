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
#include <linux/syscalls.h>
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
#include <linux/rcuwait.h>
#include <linux/compat.h>
#include <linux/io_uring.h>
#include <linux/kprobes.h>
#include <linux/rethook.h>

#include <linux/uaccess.h>
#include <asm/unistd.h>
#include <asm/mmu_context.h>
#endif

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

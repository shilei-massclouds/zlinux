// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/fork.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 *  'fork.c' contains the help-routines for the 'fork' system call
 * (see also entry.S and others).
 * Fork is rather simple, once you get the hang of it, but the memory
 * management can be a bitch. See 'mm/memory.c': 'copy_page_range()'
 */

/*
#include <linux/anon_inodes.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/user.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/stat.h>
*/
#include <linux/slab.h>
#include <linux/sched/task.h>
/*
#include <linux/sched/task_stack.h>
#include <linux/sched/cputime.h>
#include <linux/seq_file.h>
#include <linux/rtmutex.h>
*/
#include <linux/init.h>
/*
#include <linux/unistd.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/mempolicy.h>
#include <linux/sem.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/iocontext.h>
#include <linux/key.h>
#include <linux/binfmts.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/nsproxy.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/cgroup.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/seccomp.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/jiffies.h>
#include <linux/futex.h>
#include <linux/compat.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/rcupdate.h>
#include <linux/ptrace.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/memcontrol.h>
#include <linux/ftrace.h>
#include <linux/proc_fs.h>
#include <linux/profile.h>
#include <linux/rmap.h>
#include <linux/ksm.h>
#include <linux/acct.h>
#include <linux/userfaultfd_k.h>
#include <linux/tsacct_kern.h>
#include <linux/cn_proc.h>
#include <linux/freezer.h>
#include <linux/delayacct.h>
#include <linux/taskstats_kern.h>
#include <linux/random.h>
#include <linux/tty.h>
#include <linux/blkdev.h>
#include <linux/fs_struct.h>
#include <linux/magic.h>
#include <linux/perf_event.h>
#include <linux/posix-timers.h>
#include <linux/user-return-notifier.h>
#include <linux/oom.h>
#include <linux/khugepaged.h>
#include <linux/signalfd.h>
#include <linux/uprobes.h>
#include <linux/aio.h>
#include <linux/compiler.h>
#include <linux/sysctl.h>
#include <linux/kcov.h>
#include <linux/livepatch.h>
#include <linux/thread_info.h>
#include <linux/stackleak.h>
#include <linux/kasan.h>
#include <linux/scs.h>

#include <asm/pgalloc.h>
#include <linux/uaccess.h>
#include <asm/mmu_context.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
*/
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/numa.h>
#include <linux/pid.h>

static struct kmem_cache *task_struct_cachep;

static inline struct task_struct *alloc_task_struct_node(int node)
{
    return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);
}

static inline void free_task_struct(struct task_struct *tsk)
{
    kmem_cache_free(task_struct_cachep, tsk);
}

static struct task_struct *
dup_task_struct(struct task_struct *orig, int node)
{
    //int err;
    //unsigned long *stack;
    struct task_struct *tsk;
    struct vm_struct *stack_vm_area __maybe_unused;

    if (node == NUMA_NO_NODE)
        node = tsk_fork_get_node(orig);
    tsk = alloc_task_struct_node(node);
    if (!tsk)
        return NULL;

#if 0
    stack = alloc_thread_stack_node(tsk, node);
    if (!stack)
        goto free_tsk;

    if (memcg_charge_kernel_stack(tsk))
        goto free_stack;

    stack_vm_area = task_stack_vm_area(tsk);

    err = arch_dup_task_struct(tsk, orig);
#endif

    panic("%s: END!\n", __func__);
}

/*
 * This creates a new process as a copy of the old one,
 * but does not actually start it yet.
 *
 * It copies the registers, and all the appropriate
 * parts of the process environment (as per the clone
 * flags). The actual kick-off is left to the caller.
 */
static __latent_entropy struct task_struct *
copy_process(struct pid *pid, int trace, int node,
             struct kernel_clone_args *args)
{
    //int pidfd = -1, retval;
    int retval;
    struct task_struct *p;

    retval = -ENOMEM;
    p = dup_task_struct(current, node);
    if (!p)
        goto fork_out;

    panic("%s: END!\n", __func__);

fork_out:
    return ERR_PTR(retval);
}

/*
 *  Ok, this is the main fork-routine.
 *
 * It copies the process, and if successful kick-starts
 * it and waits for it to finish using the VM if required.
 *
 * args->exit_signal is expected to be checked for sanity by the caller.
 */
long _do_fork(struct kernel_clone_args *args)
{
    //long nr;
    //struct pid *pid;
    struct task_struct *p;
    //struct completion vfork;
    int trace = 0;
    //u64 clone_flags = args->flags;

    /*
     * For legacy clone() calls, CLONE_PIDFD uses the parent_tid argument
     * to return the pidfd. Hence, CLONE_PIDFD and CLONE_PARENT_SETTID are
     * mutually exclusive. With clone3() CLONE_PIDFD has grown a separate
     * field in struct clone_args and it still doesn't make sense to have
     * them both point at the same memory location. Performing this check
     * here has the advantage that we don't need to have a separate helper
     * to check for legacy clone().
     */
    if ((args->flags & CLONE_PIDFD) &&
        (args->flags & CLONE_PARENT_SETTID) &&
        (args->pidfd == args->parent_tid))
        return -EINVAL;

    p = copy_process(NULL, trace, NUMA_NO_NODE, args);

    if (IS_ERR(p))
        return PTR_ERR(p);

    panic("%s: END!\n", __func__);
}

/*
 * Create a kernel thread.
 */
pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)
{
    struct kernel_clone_args args = {
        .flags      = ((lower_32_bits(flags) | CLONE_VM |
                        CLONE_UNTRACED) & ~CSIGNAL),
        .exit_signal    = (lower_32_bits(flags) & CSIGNAL),
        .stack      = (unsigned long)fn,
        .stack_size = (unsigned long)arg,
    };

    return _do_fork(&args);
}

void __put_task_struct(struct task_struct *tsk)
{
    panic("%s: NO implementation!\n", __func__);
#if 0
    WARN_ON(!tsk->exit_state);
    WARN_ON(refcount_read(&tsk->usage));
    WARN_ON(tsk == current);

    io_uring_free(tsk);
    cgroup_free(tsk);
    task_numa_free(tsk, true);
    security_task_free(tsk);
    bpf_task_storage_free(tsk);
    exit_creds(tsk);
    delayacct_tsk_free(tsk);
    put_signal_struct(tsk->signal);
    sched_core_free(tsk);

    if (!profile_handoff_task(tsk))
        free_task(tsk);
#endif
}
EXPORT_SYMBOL_GPL(__put_task_struct);

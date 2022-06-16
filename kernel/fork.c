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

#include <linux/sched/mm.h>
/*
#include <linux/anon_inodes.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/coredump.h>
#include <linux/sched/user.h>
#include <linux/sched/numa_balancing.h>
#include <linux/sched/stat.h>
*/
#include <linux/slab.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
/*
#include <linux/sched/cputime.h>
#include <linux/seq_file.h>
#include <linux/rtmutex.h>
*/
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/cpu.h>
#include <linux/swap.h>
#include <linux/jiffies.h>
#include <linux/rcupdate.h>
/*
#include <linux/unistd.h>
#include <linux/mempolicy.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/sem.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/iocontext.h>
#include <linux/key.h>
#include <linux/binfmts.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/fs.h>
#include <linux/vmacache.h>
#include <linux/nsproxy.h>
#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/seccomp.h>
#include <linux/syscalls.h>
#include <linux/futex.h>
#include <linux/compat.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/ptrace.h>
#include <linux/mount.h>
#include <linux/audit.h>
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
#include <linux/memcontrol.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/numa.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>

struct vm_stack {
    struct rcu_head rcu;
    struct vm_struct *stack_vm_area;
};

/*
 * vmalloc() is a bit slow, and calling vfree() enough times will force a TLB
 * flush.  Try to minimize the number of calls by caching stacks.
 */
#define NR_CACHED_STACKS 2
static DEFINE_PER_CPU(struct vm_struct *, cached_stacks[NR_CACHED_STACKS]);

static struct kmem_cache *task_struct_cachep;

static inline struct task_struct *alloc_task_struct_node(int node)
{
    return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);
}

static inline void free_task_struct(struct task_struct *tsk)
{
    kmem_cache_free(task_struct_cachep, tsk);
}

static int alloc_thread_stack_node(struct task_struct *tsk, int node)
{
    int i;
    void *stack;
    struct vm_struct *vm;

    for (i = 0; i < NR_CACHED_STACKS; i++) {
        struct vm_struct *s;

        s = this_cpu_xchg(cached_stacks[i], NULL);

        if (!s)
            continue;

        stack = s->addr;

        /* Clear stale pointers from reused stack. */
        memset(stack, 0, THREAD_SIZE);

        tsk->stack_vm_area = s;
        tsk->stack = stack;
        return 0;
    }

    /*
     * Allocated stacks are cached and later reused by new threads,
     * so memcg accounting is performed manually on assigning/releasing
     * stacks to tasks. Drop __GFP_ACCOUNT.
     */
    stack = __vmalloc_node_range(THREAD_SIZE, THREAD_ALIGN,
                                 VMALLOC_START, VMALLOC_END,
                                 THREADINFO_GFP & ~__GFP_ACCOUNT,
                                 PAGE_KERNEL,
                                 0, node, __builtin_return_address(0));
    if (!stack)
        return -ENOMEM;

    vm = find_vm_area(stack);

    /*
     * We can't call find_vm_area() in interrupt context, and
     * free_thread_stack() can be called in interrupt context,
     * so cache the vm_struct.
     */
    tsk->stack_vm_area = vm;
    tsk->stack = stack;
    return 0;
}

static void account_kernel_stack(struct task_struct *tsk, int account)
{
    struct vm_struct *vm = task_stack_vm_area(tsk);
    int i;

    for (i = 0; i < THREAD_SIZE / PAGE_SIZE; i++)
        mod_lruvec_page_state(vm->pages[i], NR_KERNEL_STACK_KB,
                              account * (PAGE_SIZE / 1024));
}

void exit_task_stack_account(struct task_struct *tsk)
{
    account_kernel_stack(tsk, -1);
}

static bool try_release_thread_stack_to_cache(struct vm_struct *vm)
{
    unsigned int i;

    for (i = 0; i < NR_CACHED_STACKS; i++) {
        if (this_cpu_cmpxchg(cached_stacks[i], NULL, vm) != NULL)
            continue;
        return true;
    }
    return false;
}

static void thread_stack_free_rcu(struct rcu_head *rh)
{
    struct vm_stack *vm_stack = container_of(rh, struct vm_stack, rcu);

    if (try_release_thread_stack_to_cache(vm_stack->stack_vm_area))
        return;

    vfree(vm_stack);
}

static void thread_stack_delayed_free(struct task_struct *tsk)
{
    struct vm_stack *vm_stack = tsk->stack;

    vm_stack->stack_vm_area = tsk->stack_vm_area;
    call_rcu(&vm_stack->rcu, thread_stack_free_rcu);
}

static void free_thread_stack(struct task_struct *tsk)
{
    if (!try_release_thread_stack_to_cache(tsk->stack_vm_area))
        thread_stack_delayed_free(tsk);

    tsk->stack = NULL;
    tsk->stack_vm_area = NULL;
}

static struct task_struct *
dup_task_struct(struct task_struct *orig, int node)
{
    int err;
    struct task_struct *tsk;

    if (node == NUMA_NO_NODE)
        node = tsk_fork_get_node(orig);
    tsk = alloc_task_struct_node(node);
    if (!tsk)
        return NULL;

    err = arch_dup_task_struct(tsk, orig);
    if (err)
        goto free_tsk;

    err = alloc_thread_stack_node(tsk, node);
    if (err)
        goto free_tsk;

    refcount_set(&tsk->stack_refcount, 1);
    account_kernel_stack(tsk, 1);

#if 0
    /*
     * We must handle setting up seccomp filters once we're under
     * the sighand lock in case orig has changed between now and
     * then. Until then, filter must be NULL to avoid messing up
     * the usage counts on the error path calling free_task.
     */
    tsk->seccomp.filter = NULL;
#endif

    setup_thread_stack(tsk, orig);
    clear_tsk_need_resched(tsk);
    set_task_stack_end_magic(tsk);

#if 0
    tsk->stack_canary = get_random_canary();
#endif
    if (orig->cpus_ptr == &orig->cpus_mask)
        tsk->cpus_ptr = &tsk->cpus_mask;
    dup_user_cpus_ptr(tsk, orig, node);

    /*
     * One for the user space visible state that goes away when reaped.
     * One for the scheduler.
     */
    refcount_set(&tsk->rcu_users, 2);
    /* One for the rcu users */
    refcount_set(&tsk->usage, 1);

#if 0
    tsk->splice_pipe = NULL;
    tsk->task_frag.page = NULL;
#endif
    tsk->wake_q.next = NULL;
#if 0
    tsk->worker_private = NULL;
#endif

    return tsk;

 free_stack:
    exit_task_stack_account(tsk);
    free_thread_stack(tsk);

 free_tsk:
    free_task_struct(tsk);
    return NULL;
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
    int pidfd = -1, retval;
    struct task_struct *p;
    //struct multiprocess_signals delayed;
    struct file *pidfile = NULL;
    u64 clone_flags = args->flags;
    //struct nsproxy *nsp = current->nsproxy;

    /*
     * Don't allow sharing the root directory with processes in a different
     * namespace
     */
    if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))
        return ERR_PTR(-EINVAL);

    if ((clone_flags & (CLONE_NEWUSER|CLONE_FS)) == (CLONE_NEWUSER|CLONE_FS))
        return ERR_PTR(-EINVAL);

    /*
     * Thread groups must share signals as well, and detached threads
     * can only be started up within the thread group.
     */
    if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
        return ERR_PTR(-EINVAL);

    /*
     * Shared signal handlers imply shared VM. By way of the above,
     * thread groups also imply shared VM. Blocking this case allows
     * for various simplifications in other code.
     */
    if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
        return ERR_PTR(-EINVAL);

    /*
     * Siblings of global init remain as zombies on exit since they are
     * not reaped by their parent (swapper). To solve this and to avoid
     * multi-rooted process trees, prevent global and container-inits
     * from creating siblings.
     */
    if ((clone_flags & CLONE_PARENT) &&
        current->signal->flags & SIGNAL_UNKILLABLE)
        return ERR_PTR(-EINVAL);

    /*
     * If the new process will be in a different pid or user namespace
     * do not allow it to share a thread group with the forking task.
     */
#if 0
    if (clone_flags & CLONE_THREAD) {
        if ((clone_flags & (CLONE_NEWUSER | CLONE_NEWPID)) ||
            (task_active_pid_ns(current) != nsp->pid_ns_for_children))
            return ERR_PTR(-EINVAL);
    }

    /*
     * If the new process will be in a different time namespace
     * do not allow it to share VM or a thread group with the forking task.
     */
    if (clone_flags & (CLONE_THREAD | CLONE_VM)) {
        if (nsp->time_ns != nsp->time_ns_for_children)
            return ERR_PTR(-EINVAL);
    }
#endif

    if (clone_flags & CLONE_PIDFD) {
        /*
         * - CLONE_DETACHED is blocked so that we can potentially
         *   reuse it later for CLONE_PIDFD.
         * - CLONE_THREAD is blocked until someone really needs it.
         */
        if (clone_flags & (CLONE_DETACHED | CLONE_THREAD))
            return ERR_PTR(-EINVAL);
    }

#if 0
    /*
     * Force any signals received before this point to be delivered
     * before the fork happens.  Collect up signals sent to multiple
     * processes that happen during the fork and delay them so that
     * they appear to happen after the fork.
     */
    sigemptyset(&delayed.signal);
    INIT_HLIST_NODE(&delayed.node);

    spin_lock_irq(&current->sighand->siglock);
    if (!(clone_flags & CLONE_THREAD))
        hlist_add_head(&delayed.node, &current->signal->multiprocess);
    recalc_sigpending();
    spin_unlock_irq(&current->sighand->siglock);
    retval = -ERESTARTNOINTR;
    if (task_sigpending(current))
        goto fork_out;
#endif

    retval = -ENOMEM;
    p = dup_task_struct(current, node);
    if (!p)
        goto fork_out;

    if (args->io_thread) {
        panic("%s: NO support for io_thread\n", __func__);
#if 0
        /*
         * Mark us an IO worker, and block any signal that isn't
         * fatal or STOP
         */
        p->flags |= PF_IO_WORKER;
        siginitsetinv(&p->blocked, sigmask(SIGKILL)|sigmask(SIGSTOP));
#endif
    }

    p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ?
        args->child_tid : NULL;
    /*
     * Clear TID on mm_release()?
     */
    p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ?
        args->child_tid : NULL;

#if 0
    rt_mutex_init_task(p);
#endif

#if 0
    retval = copy_creds(p, clone_flags);
    if (retval < 0)
        goto bad_fork_free;
#endif

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
pid_t kernel_clone(struct kernel_clone_args *args)
{
    pid_t nr;
    int trace = 0;
    struct pid *pid;
    struct task_struct *p;
    //struct completion vfork;
    u64 clone_flags = args->flags;

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
        .flags = ((lower_32_bits(flags) | CLONE_VM | CLONE_UNTRACED) & ~CSIGNAL),
        .exit_signal = (lower_32_bits(flags) & CSIGNAL),
        .stack      = (unsigned long)fn,
        .stack_size = (unsigned long)arg,
    };

    return kernel_clone(&args);
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

void set_task_stack_end_magic(struct task_struct *tsk)
{
    unsigned long *stackend;

    stackend = end_of_stack(tsk);
    *stackend = STACK_END_MAGIC;    /* for overflow detection */
}

static void task_struct_whitelist(unsigned long *offset, unsigned long *size)
{
    /* Fetch thread_struct whitelist for the architecture. */
    arch_thread_struct_whitelist(offset, size);

    /*
     * Handle zero-sized whitelist or empty thread_struct, otherwise
     * adjust offset to position of thread_struct in task_struct.
     */
    if (unlikely(*size == 0))
        *offset = 0;
    else
        *offset += offsetof(struct task_struct, thread);
}

void __init fork_init(void)
{
#ifndef ARCH_MIN_TASKALIGN
#define ARCH_MIN_TASKALIGN  0
#endif

    unsigned long useroffset, usersize;
    int align = max_t(int, L1_CACHE_BYTES, ARCH_MIN_TASKALIGN);

    /* create a slab on which task_structs can be allocated */
    task_struct_whitelist(&useroffset, &usersize);
    task_struct_cachep = kmem_cache_create_usercopy("task_struct",
                                                    arch_task_struct_size, align,
                                                    SLAB_PANIC|SLAB_ACCOUNT,
                                                    useroffset, usersize, NULL);
}

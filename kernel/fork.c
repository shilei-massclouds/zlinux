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
#include <linux/sched/coredump.h>
/*
#include <linux/anon_inodes.h>
#include <linux/sched/autogroup.h>
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
#include <linux/nsproxy.h>
#include <linux/sem.h>
#include <linux/fs.h>
#include <linux/file.h>
/*
#include <linux/unistd.h>
#include <linux/mempolicy.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/iocontext.h>
#include <linux/key.h>
#include <linux/binfmts.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/security.h>
#include <linux/seccomp.h>
#include <linux/syscalls.h>
#include <linux/futex.h>
#include <linux/compat.h>
#include <linux/task_io_accounting_ops.h>
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
#include <linux/perf_event.h>
#include <linux/posix-timers.h>
#include <linux/user-return-notifier.h>
#include <linux/khugepaged.h>
#include <linux/signalfd.h>
#include <linux/uprobes.h>
#include <linux/aio.h>
#include <linux/sysctl.h>
#include <linux/kcov.h>
#include <linux/livepatch.h>
#include <linux/thread_info.h>
#include <linux/stackleak.h>
#include <linux/kasan.h>
#include <linux/scs.h>
#include <linux/ptrace.h>
*/

#include <linux/oom.h>
#include <linux/compiler.h>
#include <linux/vmacache.h>
#include <linux/mount.h>
#include <linux/blkdev.h>
#include <linux/fs_struct.h>
#include <linux/magic.h>
#include <linux/fdtable.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/numa.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/math64.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/mm_inline.h>
#include <uapi/linux/futex.h>

/*
 * Minimum number of threads to boot the kernel
 */
#define MIN_THREADS 20

/*
 * Maximum number of threads
 */
#define MAX_THREADS FUTEX_TID_MASK

#ifndef ARCH_MIN_MMSTRUCT_ALIGN
#define ARCH_MIN_MMSTRUCT_ALIGN 0
#endif

struct vm_stack {
    struct rcu_head rcu;
    struct vm_struct *stack_vm_area;
};

__cacheline_aligned DEFINE_RWLOCK(tasklist_lock);  /* outer */

/*
 * vmalloc() is a bit slow, and calling vfree() enough times will force a TLB
 * flush.  Try to minimize the number of calls by caching stacks.
 */
#define NR_CACHED_STACKS 2
static DEFINE_PER_CPU(struct vm_struct *, cached_stacks[NR_CACHED_STACKS]);

static struct kmem_cache *task_struct_cachep;

/* SLAB cache for vm_area_struct structures */
static struct kmem_cache *vm_area_cachep;

/* SLAB cache for mm_struct structures (tsk->mm) */
static struct kmem_cache *mm_cachep;

/* SLAB cache for signal_struct structures (tsk->signal) */
static struct kmem_cache *signal_cachep;

/* SLAB cache for sighand_struct structures (tsk->sighand) */
struct kmem_cache *sighand_cachep;

/* SLAB cache for files_struct structures (tsk->files) */
struct kmem_cache *files_cachep;

/* SLAB cache for fs_struct structures (tsk->fs) */
struct kmem_cache *fs_cachep;

/*
 * Protected counters by write_lock_irq(&tasklist_lock)
 */
unsigned long total_forks;  /* Handle normal Linux uptimes. */
int nr_threads;             /* The idle threads do not count.. */

static int max_threads;     /* tunable limit on nr_threads */

static unsigned long default_dump_filter = MMF_DUMP_FILTER_DEFAULT;

static inline struct task_struct *alloc_task_struct_node(int node)
{
    return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);
}

#define allocate_mm()   (kmem_cache_alloc(mm_cachep, GFP_KERNEL))
#define free_mm(mm)     (kmem_cache_free(mm_cachep, (mm)))

static struct mm_struct *
mm_init(struct mm_struct *mm, struct task_struct *p,
        struct user_namespace *user_ns);

static void mm_init_owner(struct mm_struct *mm, struct task_struct *p)
{
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
    tsk->worker_private = NULL;

    return tsk;

 free_stack:
    exit_task_stack_account(tsk);
    free_thread_stack(tsk);

 free_tsk:
    free_task_struct(tsk);
    return NULL;
}

static inline void init_task_pid_links(struct task_struct *task)
{
    enum pid_type type;

    for (type = PIDTYPE_PID; type < PIDTYPE_MAX; ++type)
        INIT_HLIST_NODE(&task->pid_links[type]);
}

static inline void
init_task_pid(struct task_struct *task, enum pid_type type, struct pid *pid)
{
    if (type == PIDTYPE_PID)
        task->thread_pid = pid;
    else
        task->signal->pids[type] = pid;
}

static void rt_mutex_init_task(struct task_struct *p)
{
    raw_spin_lock_init(&p->pi_lock);
    p->pi_waiters = RB_ROOT_CACHED;
    p->pi_top_task = NULL;
    p->pi_blocked_on = NULL;
}

static int copy_sighand(unsigned long clone_flags,
                        struct task_struct *tsk)
{
    struct sighand_struct *sig;

    if (clone_flags & CLONE_SIGHAND) {
        refcount_inc(&current->sighand->count);
        return 0;
    }
    sig = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
    RCU_INIT_POINTER(tsk->sighand, sig);
    if (!sig)
        return -ENOMEM;

    refcount_set(&sig->count, 1);
    spin_lock_irq(&current->sighand->siglock);
    memcpy(sig->action, current->sighand->action, sizeof(sig->action));
    spin_unlock_irq(&current->sighand->siglock);

    /* Reset all signal handler not set to SIG_IGN to SIG_DFL. */
    if (clone_flags & CLONE_CLEAR_SIGHAND)
        flush_signal_handlers(tsk, 0);

    return 0;
}

static int copy_fs(unsigned long clone_flags, struct task_struct *tsk)
{
    struct fs_struct *fs = current->fs;
    if (clone_flags & CLONE_FS) {
        /* tsk->fs is already what we want */
        spin_lock(&fs->lock);
        if (fs->in_exec) {
            spin_unlock(&fs->lock);
            return -EAGAIN;
        }
        fs->users++;
        spin_unlock(&fs->lock);
        return 0;
    }
    tsk->fs = copy_fs_struct(fs);
    if (!tsk->fs)
        return -ENOMEM;
    return 0;
}

static int copy_files(unsigned long clone_flags,
                      struct task_struct *tsk)
{
    struct files_struct *oldf, *newf;
    int error = 0;

    /*
     * A background process may not have any files ...
     */
    oldf = current->files;
    if (!oldf)
        goto out;

    if (clone_flags & CLONE_FILES) {
        atomic_inc(&oldf->count);
        goto out;
    }

    newf = dup_fd(oldf, NR_OPEN_MAX, &error);
    if (!newf)
        goto out;

    tsk->files = newf;
    error = 0;
out:
    return error;
}

static __latent_entropy int dup_mmap(struct mm_struct *mm,
                                     struct mm_struct *oldmm)
{
    struct vm_area_struct *mpnt, *tmp, *prev, **pprev;
    struct rb_node **rb_link, *rb_parent;
    int retval;
    unsigned long charge;
    LIST_HEAD(uf);

    panic("%s: END!\n", __func__);
}

/**
 * dup_mm() - duplicates an existing mm structure
 * @tsk: the task_struct with which the new mm will be associated.
 * @oldmm: the mm to duplicate.
 *
 * Allocates a new mm structure and duplicates the provided @oldmm structure
 * content into it.
 *
 * Return: the duplicated mm or NULL on failure.
 */
static struct mm_struct *dup_mm(struct task_struct *tsk,
                                struct mm_struct *oldmm)
{
    struct mm_struct *mm;
    int err;

    mm = allocate_mm();
    if (!mm)
        goto fail_nomem;

    memcpy(mm, oldmm, sizeof(*mm));

    if (!mm_init(mm, tsk, mm->user_ns))
        goto fail_nomem;

    err = dup_mmap(mm, oldmm);
    if (err)
        goto free_pt;

    panic("%s: ERROR!\n", __func__);
    return mm;

 free_pt:
    /* don't put binfmt in mmput, we haven't got module yet */
    mm->binfmt = NULL;
    mm_init_owner(mm, NULL);
    mmput(mm);

 fail_nomem:
    return NULL;
}

static int copy_mm(unsigned long clone_flags, struct task_struct *tsk)
{
    struct mm_struct *mm, *oldmm;

    tsk->min_flt = tsk->maj_flt = 0;
    tsk->nvcsw = tsk->nivcsw = 0;
    tsk->last_switch_count = tsk->nvcsw + tsk->nivcsw;
    tsk->last_switch_time = 0;

    tsk->mm = NULL;
    tsk->active_mm = NULL;

    /*
     * Are we cloning a kernel thread?
     *
     * We need to steal a active VM for that..
     */
    oldmm = current->mm;
    if (!oldmm)
        return 0;

    /* initialize the new vmacache entries */
    vmacache_flush(tsk);

    if (clone_flags & CLONE_VM) {
        mmget(oldmm);
        mm = oldmm;
    } else {
        mm = dup_mm(tsk, current->mm);
        if (!mm)
            return -ENOMEM;
    }

    tsk->mm = mm;
    tsk->active_mm = mm;
    return 0;
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
    struct nsproxy *nsp = current->nsproxy;

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
    if (clone_flags & CLONE_THREAD) {
        if ((clone_flags & (CLONE_NEWUSER | CLONE_NEWPID)) ||
            (task_active_pid_ns(current) != nsp->pid_ns_for_children))
            return ERR_PTR(-EINVAL);
    }

#if 0
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

    rt_mutex_init_task(p);

#if 0
    retval = copy_creds(p, clone_flags);
    if (retval < 0)
        goto bad_fork_free;

    retval = -EAGAIN;
    if (is_ucounts_overlimit(task_ucounts(p), UCOUNT_RLIMIT_NPROC, rlimit(RLIMIT_NPROC))) {
        if (p->real_cred->user != INIT_USER &&
            !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN))
            goto bad_fork_cleanup_count;
    }
#endif
    current->flags &= ~PF_NPROC_EXCEEDED;

    /*
     * If multiple threads are within copy_process(), then this check
     * triggers too late. This doesn't hurt, the check is only there
     * to stop root fork bombs.
     */
    retval = -EAGAIN;
    if (data_race(nr_threads >= max_threads))
        goto bad_fork_cleanup_count;

    p->flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER | PF_IDLE | PF_NO_SETAFFINITY);
    p->flags |= PF_FORKNOEXEC;
    INIT_LIST_HEAD(&p->children);
    INIT_LIST_HEAD(&p->sibling);
    p->vfork_done = NULL;
    spin_lock_init(&p->alloc_lock);

#if 0
    init_sigpending(&p->pending);

    p->utime = p->stime = p->gtime = 0;
#endif

#if 0
    p->io_uring = NULL;
    memset(&p->rss_stat, 0, sizeof(p->rss_stat));
#endif

    p->default_timer_slack_ns = current->timer_slack_ns;

#if 0
    posix_cputimers_init(&p->posix_cputimers);
#endif

#if 0
    p->io_context = NULL;
    cgroup_fork(p);
#endif
    if (p->flags & PF_KTHREAD) {
        if (!set_kthread_struct(p))
            goto bad_fork_cleanup_delayacct;
    }

    p->pagefault_disabled = 0;

#if 0
    RCU_INIT_POINTER(p->bpf_storage, NULL);
    p->bpf_ctx = NULL;
#endif

    /* Perform scheduler related setup. Assign this task to a CPU. */
    retval = sched_fork(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_policy;

#if 0
    retval = perf_event_init_task(p, clone_flags);
    if (retval)
        goto bad_fork_cleanup_policy;
#endif
    /* copy all the process information */
    shm_init_task(p);
#if 0
    retval = copy_semundo(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_security;
#endif
    retval = copy_files(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_semundo;
    retval = copy_fs(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_files;
    retval = copy_sighand(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_fs;
#if 0
    retval = copy_signal(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_sighand;
#endif
    retval = copy_mm(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_signal;
#if 0
    retval = copy_namespaces(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_mm;
    retval = copy_io(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_namespaces;
#endif

    retval = copy_thread(clone_flags, args->stack, args->stack_size,
                         p, args->tls);
    if (retval)
        goto bad_fork_cleanup_io;

    if (pid != &init_struct_pid) {
        pid = alloc_pid(p->nsproxy->pid_ns_for_children,
                        args->set_tid, args->set_tid_size);
        if (IS_ERR(pid)) {
            retval = PTR_ERR(pid);
            goto bad_fork_cleanup_thread;
        }
    }

    /* ok, now we should be set up.. */
    p->pid = pid_nr(pid);
    if (clone_flags & CLONE_THREAD) {
        p->group_leader = current->group_leader;
        p->tgid = current->tgid;
    } else {
        p->group_leader = p;
        p->tgid = p->pid;
    }

    p->nr_dirtied = 0;
    p->nr_dirtied_pause = 128 >> (PAGE_SHIFT - 10);
    p->dirty_paused_when = 0;

    p->pdeath_signal = 0;
    INIT_LIST_HEAD(&p->thread_group);
    p->task_works = NULL;

#if 0
    /*
     * Ensure that the cgroup subsystem policies allow the new process to be
     * forked. It should be noted that the new process's css_set can be changed
     * between here and cgroup_post_fork() if an organisation operation is in
     * progress.
     */
    retval = cgroup_can_fork(p, args);
    if (retval)
        goto bad_fork_put_pidfd;

    /*
     * Now that the cgroups are pinned, re-clone the parent cgroup and put
     * the new task on the correct runqueue. All this *before* the task
     * becomes visible.
     *
     * This isn't part of ->can_fork() because while the re-cloning is
     * cgroup specific, it unconditionally needs to place the task on a
     * runqueue.
     */
    sched_cgroup_fork(p, args);

    /*
     * From this point on we must avoid any synchronous user-space
     * communication until we take the tasklist-lock. In particular, we do
     * not want user-space to be able to predict the process start-time by
     * stalling fork(2) after we recorded the start_time but before it is
     * visible to the system.
     */

    p->start_time = ktime_get_ns();
    p->start_boottime = ktime_get_boottime_ns();
#endif

    /*
     * Make it visible to the rest of the system, but dont wake it up yet.
     * Need tasklist lock for parent etc handling!
     */
    write_lock_irq(&tasklist_lock);

    /* CLONE_PARENT re-uses the old parent */
    if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {
        p->real_parent = current->real_parent;
        p->parent_exec_id = current->parent_exec_id;
        if (clone_flags & CLONE_THREAD)
            p->exit_signal = -1;
        else
            p->exit_signal = current->group_leader->exit_signal;
    } else {
        p->real_parent = current;
        p->parent_exec_id = current->self_exec_id;
        p->exit_signal = args->exit_signal;
    }

#if 0
    spin_lock(&current->sighand->siglock);

    /*
     * Copy seccomp details explicitly here, in case they were changed
     * before holding sighand lock.
     */
    copy_seccomp(p);

    rseq_fork(p, clone_flags);

    /* Don't start children in a dying pid namespace */
    if (unlikely(!(ns_of_pid(pid)->pid_allocated & PIDNS_ADDING))) {
        retval = -ENOMEM;
        goto bad_fork_cancel_cgroup;
    }

    /* Let kill terminate clone/fork in the middle */
    if (fatal_signal_pending(current)) {
        retval = -EINTR;
        goto bad_fork_cancel_cgroup;
    }
#endif

    init_task_pid_links(p);
    if (likely(p->pid)) {
#if 0
        ptrace_init_task(p, (clone_flags & CLONE_PTRACE) || trace);
#endif

        init_task_pid(p, PIDTYPE_PID, pid);
        if (thread_group_leader(p)) {
            pr_warn("%s: thread_group_leader!\n", __func__);
        } else {
            panic("%s: !thread_group_leader\n", __func__);
        }
        attach_pid(p, PIDTYPE_PID);
        nr_threads++;
    }

    total_forks++;
#if 0
    hlist_del_init(&delayed.node);
    spin_unlock(&current->sighand->siglock);
    syscall_tracepoint_update(p);
#endif
    write_unlock_irq(&tasklist_lock);

#if 0
    if (pidfile)
        fd_install(pidfd, pidfile);

    cgroup_post_fork(p, args);
    perf_event_fork(p);

    copy_oom_score_adj(clone_flags, p);
#endif

    return p;

//bad_fork_cancel_cgroup:
    //sched_core_free(p);
    spin_unlock(&current->sighand->siglock);
    write_unlock_irq(&tasklist_lock);
    //cgroup_cancel_fork(p, args);
//bad_fork_put_pidfd:
#if 0
    if (clone_flags & CLONE_PIDFD) {
        fput(pidfile);
        put_unused_fd(pidfd);
    }
#endif
//bad_fork_free_pid:
#if 0
    if (pid != &init_struct_pid)
        free_pid(pid);
#endif
 bad_fork_cleanup_thread:
    //exit_thread(p);
 bad_fork_cleanup_io:
#if 0
    if (p->io_context)
        exit_io_context(p);
#endif
//bad_fork_cleanup_namespaces:
    //exit_task_namespaces(p);
 bad_fork_cleanup_mm:
    if (p->mm) {
        //mm_clear_owner(p->mm, p);
        mmput(p->mm);
    }
 bad_fork_cleanup_signal:
#if 0
    if (!(clone_flags & CLONE_THREAD))
        free_signal_struct(p->signal);
#endif
 bad_fork_cleanup_sighand:
    //__cleanup_sighand(p->sighand);
 bad_fork_cleanup_fs:
    //exit_fs(p); /* blocking */
 bad_fork_cleanup_files:
    //exit_files(p); /* blocking */
 bad_fork_cleanup_semundo:
    //exit_sem(p);
//bad_fork_cleanup_security:
//bad_fork_cleanup_audit:
//bad_fork_cleanup_perf:
    //perf_event_free_task(p);
 bad_fork_cleanup_policy:
 bad_fork_cleanup_delayacct:
    //delayacct_tsk_free(p);
 bad_fork_cleanup_count:
    //dec_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);
    //exit_creds(p);
 bad_fork_free:
    WRITE_ONCE(p->__state, TASK_DEAD);
    exit_task_stack_account(p);
    put_task_stack(p);
    //delayed_free_task(p);
 fork_out:
    panic("%s: ERROR!\n", __func__);
    spin_lock_irq(&current->sighand->siglock);
    //hlist_del_init(&delayed.node);
    spin_unlock_irq(&current->sighand->siglock);
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

    pid = get_task_pid(p, PIDTYPE_PID);
    nr = pid_vnr(pid);

#if 0
    if (clone_flags & CLONE_PARENT_SETTID)
        put_user(nr, args->parent_tid);

    if (clone_flags & CLONE_VFORK) {
        p->vfork_done = &vfork;
        init_completion(&vfork);
        get_task_struct(p);
    }
#endif

    wake_up_new_task(p);

    /* forking complete and child started to run, tell ptracer */
    if (unlikely(trace)) {
        panic("%s: no TRACE!\n", __func__);
        //ptrace_event_pid(trace, pid);
    }

    if (clone_flags & CLONE_VFORK) {
        panic("%s: no CLONE_VFORK!\n", __func__);
#if 0
        if (!wait_for_vfork_done(p, &vfork))
            ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, pid);
#endif
    }

    put_pid(pid);
    pr_warn("%s: pid(%d) END!\n", __func__, nr);
    return nr;
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

/*
 * Called when the last reference to the mm
 * is dropped: either by a lazy thread or by
 * mmput. Free the page directory and the mm.
 */
void __mmdrop(struct mm_struct *mm)
{
#if 0
    BUG_ON(mm == &init_mm);
    WARN_ON_ONCE(mm == current->mm);
    WARN_ON_ONCE(mm == current->active_mm);
    mm_free_pgd(mm);
    destroy_context(mm);
    mmu_notifier_subscriptions_destroy(mm);
    check_mm(mm);
    put_user_ns(mm->user_ns);
    mm_pasid_drop(mm);
    free_mm(mm);
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(__mmdrop);

static void release_task_stack(struct task_struct *tsk)
{
    if (WARN_ON(READ_ONCE(tsk->__state) != TASK_DEAD))
        return;  /* Better to leak the stack than to free prematurely */

    free_thread_stack(tsk);
}

void put_task_stack(struct task_struct *tsk)
{
    if (refcount_dec_and_test(&tsk->stack_refcount))
        release_task_stack(tsk);
}

/*
 * set_max_threads
 */
static void set_max_threads(unsigned int max_threads_suggested)
{
    u64 threads;
    unsigned long nr_pages = totalram_pages();

    /*
     * The number of threads shall be limited such that the thread
     * structures may only consume a small part of the available memory.
     */
    if (fls64(nr_pages) + fls64(PAGE_SIZE) > 64)
        threads = MAX_THREADS;
    else
        threads = div64_u64((u64) nr_pages * (u64) PAGE_SIZE,
                            (u64) THREAD_SIZE * 8UL);

    if (threads > max_threads_suggested)
        threads = max_threads_suggested;

    max_threads = clamp_t(u64, threads, MIN_THREADS, MAX_THREADS);
}

static void mm_init_aio(struct mm_struct *mm)
{
    spin_lock_init(&mm->ioctx_lock);
    mm->ioctx_table = NULL;
}

static inline int mm_alloc_pgd(struct mm_struct *mm)
{
    mm->pgd = pgd_alloc(mm);
    if (unlikely(!mm->pgd))
        return -ENOMEM;
    return 0;
}

static inline void mm_free_pgd(struct mm_struct *mm)
{
    pgd_free(mm, mm->pgd);
}

static struct mm_struct *
mm_init(struct mm_struct *mm, struct task_struct *p,
        struct user_namespace *user_ns)
{
    mm->mmap = NULL;
    mm->mm_rb = RB_ROOT;
    mm->vmacache_seqnum = 0;
    atomic_set(&mm->mm_users, 1);
    atomic_set(&mm->mm_count, 1);
    seqcount_init(&mm->write_protect_seq);
    mmap_init_lock(mm);
    INIT_LIST_HEAD(&mm->mmlist);
    mm_pgtables_bytes_init(mm);
    mm->map_count = 0;
    mm->locked_vm = 0;
    atomic64_set(&mm->pinned_vm, 0);
#if 0
    memset(&mm->rss_stat, 0, sizeof(mm->rss_stat));
#endif
    spin_lock_init(&mm->page_table_lock);
    spin_lock_init(&mm->arg_lock);
    mm_init_cpumask(mm);
    mm_init_aio(mm);
    RCU_INIT_POINTER(mm->exe_file, NULL);
#if 0
    mmu_notifier_subscriptions_init(mm);
#endif
    init_tlb_flush_pending(mm);
    hugetlb_count_init(mm);

    if (current->mm) {
        mm->flags = current->mm->flags & MMF_INIT_MASK;
        mm->def_flags = current->mm->def_flags & VM_INIT_DEF_MASK;
    } else {
        mm->flags = default_dump_filter;
        mm->def_flags = 0;
    }

    if (mm_alloc_pgd(mm))
        goto fail_nopgd;

    if (init_new_context(p, mm))
        goto fail_nocontext;

    mm->user_ns = get_user_ns(user_ns);
    return mm;

fail_nocontext:
    mm_free_pgd(mm);
fail_nopgd:
    free_mm(mm);
    return NULL;
}

/*
 * Allocate and initialize an mm_struct.
 */
struct mm_struct *mm_alloc(void)
{
    struct mm_struct *mm;

    mm = allocate_mm();
    if (!mm)
        return NULL;

    memset(mm, 0, sizeof(*mm));
    return mm_init(mm, current, current_user_ns());
}

struct vm_area_struct *vm_area_alloc(struct mm_struct *mm)
{
    struct vm_area_struct *vma;

    vma = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);
    if (vma)
        vma_init(vma, mm);
    return vma;
}

void vm_area_free(struct vm_area_struct *vma)
{
    kmem_cache_free(vm_area_cachep, vma);
}

static inline void __mmput(struct mm_struct *mm)
{
    VM_BUG_ON(atomic_read(&mm->mm_users));

#if 0
    uprobe_clear_state(mm);
    exit_aio(mm);
    ksm_exit(mm);
    khugepaged_exit(mm); /* must run before exit_mmap */
    exit_mmap(mm);
    mm_put_huge_zero_page(mm);
    set_mm_exe_file(mm, NULL);
    if (!list_empty(&mm->mmlist)) {
        spin_lock(&mmlist_lock);
        list_del(&mm->mmlist);
        spin_unlock(&mmlist_lock);
    }
    if (mm->binfmt)
        module_put(mm->binfmt->module);
    mmdrop(mm);
#endif

    panic("%s: ERROR!\n", __func__);
}

/*
 * Decrement the use count and release all resources for an mm.
 */
void mmput(struct mm_struct *mm)
{
    might_sleep();

    if (atomic_dec_and_test(&mm->mm_users))
        __mmput(mm);
}
EXPORT_SYMBOL_GPL(mmput);

/*
 * Unshare file descriptor table if it is being shared
 */
int unshare_fd(unsigned long unshare_flags, unsigned int max_fds,
               struct files_struct **new_fdp)
{
    struct files_struct *fd = current->files;
    int error = 0;

    if ((unshare_flags & CLONE_FILES) &&
        (fd && atomic_read(&fd->count) > 1)) {
        *new_fdp = dup_fd(fd, max_fds, &error);
        if (!*new_fdp)
            return error;
    }

    return 0;
}

/*
 *  Helper to unshare the files of the current task.
 *  We don't want to expose copy_files internals to
 *  the exec layer of the kernel.
 */

int unshare_files(void)
{
    struct task_struct *task = current;
    struct files_struct *old, *copy = NULL;
    int error;

    error = unshare_fd(CLONE_FILES, NR_OPEN_MAX, &copy);
    if (error || !copy)
        return error;

    old = task->files;
    task_lock(task);
    task->files = copy;
    task_unlock(task);
    put_files_struct(old);
    return 0;
}

/**
 * set_mm_exe_file - change a reference to the mm's executable file
 *
 * This changes mm's executable file (shown as symlink /proc/[pid]/exe).
 *
 * Main users are mmput() and sys_execve(). Callers prevent concurrent
 * invocations: in mmput() nobody alive left, in execve task is single
 * threaded.
 *
 * Can only fail if new_exe_file != NULL.
 */
int set_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file)
{
    struct file *old_exe_file;

    /*
     * It is safe to dereference the exe_file without RCU as
     * this function is only called if nobody else can access
     * this mm -- see comment above for justification.
     */
    old_exe_file = rcu_dereference_raw(mm->exe_file);

    if (new_exe_file) {
        /*
         * We expect the caller (i.e., sys_execve) to already denied
         * write access, so this is unlikely to fail.
         */
        if (unlikely(deny_write_access(new_exe_file)))
            return -EACCES;
        get_file(new_exe_file);
    }
    rcu_assign_pointer(mm->exe_file, new_exe_file);
    if (old_exe_file) {
        allow_write_access(old_exe_file);
        fput(old_exe_file);
    }
    return 0;
}

static void complete_vfork_done(struct task_struct *tsk)
{
    struct completion *vfork;

    task_lock(tsk);
    vfork = tsk->vfork_done;
    if (likely(vfork)) {
        tsk->vfork_done = NULL;
        complete(vfork);
    }
    task_unlock(tsk);
}

/* Please note the differences between mmput and mm_release.
 * mmput is called whenever we stop holding onto a mm_struct,
 * error success whatever.
 *
 * mm_release is called after a mm_struct has been removed
 * from the current process.
 *
 * This difference is important for error handling, when we
 * only half set up a mm_struct for a new process and need to restore
 * the old one.  Because we mmput the new mm_struct before
 * restoring the old one. . .
 * Eric Biederman 10 January 1998
 */
static void mm_release(struct task_struct *tsk, struct mm_struct *mm)
{
    /*
     * Signal userspace if we're not exiting with a core dump
     * because we want to leave the value intact for debugging
     * purposes.
     */
    if (tsk->clear_child_tid) {
        panic("%s: tsk->clear_child_tid!\n", __func__);
    }

    /*
     * All done, finally we can wake up parent and return this mm to him.
     * Also kthread_stop() uses this completion for synchronization.
     */
    if (tsk->vfork_done)
        complete_vfork_done(tsk);
}

void exec_mm_release(struct task_struct *tsk, struct mm_struct *mm)
{
    //futex_exec_release(tsk);
    mm_release(tsk, mm);
}

struct vm_area_struct *vm_area_dup(struct vm_area_struct *orig)
{
    struct vm_area_struct *new = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);

    if (new) {
        /*
         * orig->shared.rb may be modified concurrently, but the clone
         * will be reinitialized.
         */
        *new = data_race(*orig);
        INIT_LIST_HEAD(&new->anon_vma_chain);
        new->vm_next = new->vm_prev = NULL;
        dup_anon_vma_name(orig, new);
    }
    return new;
}

static void sighand_ctor(void *data)
{
    struct sighand_struct *sighand = data;

    spin_lock_init(&sighand->siglock);
    init_waitqueue_head(&sighand->signalfd_wqh);
}

void __init proc_caches_init(void)
{
    unsigned int mm_size;

    sighand_cachep = kmem_cache_create("sighand_cache",
            sizeof(struct sighand_struct), 0,
            SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_TYPESAFE_BY_RCU|
            SLAB_ACCOUNT, sighand_ctor);
    signal_cachep = kmem_cache_create("signal_cache",
            sizeof(struct signal_struct), 0,
            SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT,
            NULL);

    /*
     * The mm_cpumask is located at the end of mm_struct, and is
     * dynamically sized based on the maximum CPU number this system
     * can have, taking hotplug into account (nr_cpu_ids).
     */
    mm_size = sizeof(struct mm_struct) + cpumask_size();

    mm_cachep = kmem_cache_create_usercopy("mm_struct",
            mm_size, ARCH_MIN_MMSTRUCT_ALIGN,
            SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT,
            offsetof(struct mm_struct, saved_auxv),
            sizeof_field(struct mm_struct, saved_auxv),
            NULL);
    files_cachep =
        kmem_cache_create("files_cache",
                          sizeof(struct files_struct), 0,
                          SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT,
                          NULL);
    fs_cachep =
        kmem_cache_create("fs_cache", sizeof(struct fs_struct), 0,
                          SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_ACCOUNT,
                          NULL);

    vm_area_cachep = KMEM_CACHE(vm_area_struct,
                                SLAB_PANIC|SLAB_ACCOUNT);
    mmap_init();
    nsproxy_cache_init();
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

    set_max_threads(MAX_THREADS);

    init_task.signal->rlim[RLIMIT_NPROC].rlim_cur = max_threads/2;
    init_task.signal->rlim[RLIMIT_NPROC].rlim_max = max_threads/2;
    init_task.signal->rlim[RLIMIT_SIGPENDING] =
        init_task.signal->rlim[RLIMIT_NPROC];
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/signal.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  1997-11-02  Modified for POSIX.1b signals by Richard Henderson
 *
 *  2003-06-02  Jim Houston - Concurrent Computer Corp.
 *      Changes to use preallocated sigqueue structures
 *      to allow signals to be sent reliably.
 */

#include <linux/slab.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/user.h>
#include <linux/sched/debug.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
//#include <linux/sched/cputime.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#if 0
#include <linux/tty.h>
#endif
#include <linux/binfmts.h>
#if 0
#include <linux/coredump.h>
#include <linux/security.h>
#endif
#include <linux/syscalls.h>
#include <linux/ptrace.h>
#include <linux/signal.h>
#include <linux/signalfd.h>
#include <linux/ratelimit.h>
#include <linux/task_work.h>
#if 0
#include <linux/capability.h>
#include <linux/freezer.h>
#endif
#include <linux/pid_namespace.h>
#include <linux/nsproxy.h>
#include <linux/user_namespace.h>
//#include <linux/uprobes.h>
#include <linux/compat.h>
//#include <linux/cn_proc.h>
#include <linux/compiler.h>
#if 0
#include <linux/posix-timers.h>
#include <linux/audit.h>
#endif
#include <linux/cgroup.h>

#include <asm/param.h>
#include <linux/uaccess.h>
#if 0
#include <asm/unistd.h>
#include <asm/siginfo.h>
#endif
#include <asm/cacheflush.h>
//#include <asm/syscall.h>    /* for syscall_get_* */

#define CREATE_TRACE_POINTS
#include <trace/events/signal.h>

enum sig_handler {
    HANDLER_CURRENT, /* If reachable use the current handler */
    HANDLER_SIG_DFL, /* Always use SIG_DFL handler semantics */
    HANDLER_EXIT,    /* Only visible as the process exit code */
};

static const struct {
    unsigned char limit, layout;
} sig_sicodes[] = {
    [SIGILL]  = { NSIGILL,  SIL_FAULT },
    [SIGFPE]  = { NSIGFPE,  SIL_FAULT },
    [SIGSEGV] = { NSIGSEGV, SIL_FAULT },
    [SIGBUS]  = { NSIGBUS,  SIL_FAULT },
    [SIGTRAP] = { NSIGTRAP, SIL_FAULT },
    [SIGCHLD] = { NSIGCHLD, SIL_CHLD },
    [SIGPOLL] = { NSIGPOLL, SIL_POLL },
    [SIGSYS]  = { NSIGSYS,  SIL_SYS },
};

/*
 * SLAB caches for signal bits.
 */

static struct kmem_cache *sigqueue_cachep;

int print_fatal_signals __read_mostly;

/*
 * Flush all handlers for a task.
 */

void
flush_signal_handlers(struct task_struct *t, int force_default)
{
    int i;
    struct k_sigaction *ka = &t->sighand->action[0];
    for (i = _NSIG ; i != 0 ; i--) {
        if (force_default || ka->sa.sa_handler != SIG_IGN)
            ka->sa.sa_handler = SIG_DFL;
        ka->sa.sa_flags = 0;
        sigemptyset(&ka->sa.sa_mask);
        ka++;
    }
}

/*
 * Re-calculate pending state from the set of locally pending
 * signals, globally pending signals, and blocked signals.
 */
static inline
bool has_pending_signals(sigset_t *signal, sigset_t *blocked)
{
    unsigned long ready;
    long i;

    switch (_NSIG_WORDS) {
    default:
        for (i = _NSIG_WORDS, ready = 0; --i >= 0 ;)
            ready |= signal->sig[i] &~ blocked->sig[i];
        break;

    case 4: ready  = signal->sig[3] &~ blocked->sig[3];
        ready |= signal->sig[2] &~ blocked->sig[2];
        ready |= signal->sig[1] &~ blocked->sig[1];
        ready |= signal->sig[0] &~ blocked->sig[0];
        break;

    case 2: ready  = signal->sig[1] &~ blocked->sig[1];
        ready |= signal->sig[0] &~ blocked->sig[0];
        break;

    case 1: ready  = signal->sig[0] &~ blocked->sig[0];
    }
    return ready != 0;
}

#define PENDING(p,b) has_pending_signals(&(p)->signal, (b))

static bool recalc_sigpending_tsk(struct task_struct *t)
{
    if ((t->jobctl & (JOBCTL_PENDING_MASK | JOBCTL_TRAP_FREEZE)) ||
        PENDING(&t->pending, &t->blocked) ||
        PENDING(&t->signal->shared_pending, &t->blocked) ||
        cgroup_task_frozen(t)) {
        set_tsk_thread_flag(t, TIF_SIGPENDING);
        return true;
    }

    /*
     * We must never clear the flag in another thread, or in current
     * when it's possible the current syscall is returning -ERESTART*.
     * So we don't clear it here, and only callers who know they should do.
     */
    return false;
}

/*
 * After recalculating TIF_SIGPENDING, we need to make sure the task wakes up.
 * This is superfluous when called on current, the wakeup is a harmless no-op.
 */
void recalc_sigpending_and_wake(struct task_struct *t)
{
    if (recalc_sigpending_tsk(t))
        signal_wake_up(t, 0);
}

enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
{
    enum siginfo_layout layout = SIL_KILL;
    if ((si_code > SI_USER) && (si_code < SI_KERNEL)) {
        if ((sig < ARRAY_SIZE(sig_sicodes)) &&
            (si_code <= sig_sicodes[sig].limit)) {
            layout = sig_sicodes[sig].layout;
            /* Handle the exceptions */
            if ((sig == SIGBUS) &&
                (si_code >= BUS_MCEERR_AR) && (si_code <= BUS_MCEERR_AO))
                layout = SIL_FAULT_MCEERR;
            else if ((sig == SIGSEGV) && (si_code == SEGV_BNDERR))
                layout = SIL_FAULT_BNDERR;
            else if ((sig == SIGSEGV) && (si_code == SEGV_PKUERR))
                layout = SIL_FAULT_PKUERR;
            else if ((sig == SIGTRAP) && (si_code == TRAP_PERF))
                layout = SIL_FAULT_PERF_EVENT;
            else if (IS_ENABLED(CONFIG_SPARC) &&
                 (sig == SIGILL) && (si_code == ILL_ILLTRP))
                layout = SIL_FAULT_TRAPNO;
            else if (IS_ENABLED(CONFIG_ALPHA) &&
                 ((sig == SIGFPE) ||
                  ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
                layout = SIL_FAULT_TRAPNO;
        }
        else if (si_code <= NSIGPOLL)
            layout = SIL_POLL;
    } else {
        if (si_code == SI_TIMER)
            layout = SIL_TIMER;
        else if (si_code == SI_SIGIO)
            layout = SIL_POLL;
        else if (si_code < 0)
            layout = SIL_RT;
    }
    return layout;
}

static inline bool has_si_pid_and_uid(struct kernel_siginfo *info)
{
    bool ret = false;
    switch (siginfo_layout(info->si_signo, info->si_code)) {
    case SIL_KILL:
    case SIL_CHLD:
    case SIL_RT:
        ret = true;
        break;
    case SIL_TIMER:
    case SIL_POLL:
    case SIL_FAULT:
    case SIL_FAULT_TRAPNO:
    case SIL_FAULT_MCEERR:
    case SIL_FAULT_BNDERR:
    case SIL_FAULT_PKUERR:
    case SIL_FAULT_PERF_EVENT:
    case SIL_SYS:
        ret = false;
        break;
    }
    return ret;
}

static void __user *sig_handler(struct task_struct *t, int sig)
{
    return t->sighand->action[sig - 1].sa.sa_handler;
}

static inline bool sig_handler_ignored(void __user *handler, int sig)
{
    /* Is it explicitly or implicitly ignored? */
    return handler == SIG_IGN ||
        (handler == SIG_DFL && sig_kernel_ignore(sig));
}

static bool sig_task_ignored(struct task_struct *t, int sig, bool force)
{
    void __user *handler;

    handler = sig_handler(t, sig);

    /* SIGKILL and SIGSTOP may not be sent to the global init */
    if (unlikely(is_global_init(t) && sig_kernel_only(sig)))
        return true;

    if (unlikely(t->signal->flags & SIGNAL_UNKILLABLE) &&
        handler == SIG_DFL && !(force && sig_kernel_only(sig)))
        return true;

    /* Only allow kernel generated signals to this kthread */
    if (unlikely((t->flags & PF_KTHREAD) &&
                 (handler == SIG_KTHREAD_KERNEL) && !force))
        return true;

    return sig_handler_ignored(handler, sig);
}

static bool sig_ignored(struct task_struct *t, int sig, bool force)
{
    /*
     * Blocked signals are never ignored, since the
     * signal handler may change by the time it is
     * unblocked.
     */
    if (sigismember(&t->blocked, sig) ||
        sigismember(&t->real_blocked, sig))
        return false;

    /*
     * Tracers may want to know about even ignored signal unless it
     * is SIGKILL which can't be reported anyway but can be ignored
     * by SIGNAL_UNKILLABLE task.
     */
    if (t->ptrace && sig != SIGKILL)
        return false;

    return sig_task_ignored(t, sig, force);
}

/*
 * Handle magic process-wide effects of stop/continue signals. Unlike
 * the signal actions, these happen immediately at signal-generation
 * time regardless of blocking, ignoring, or handling.  This does the
 * actual continuing for SIGCONT, but not the actual stopping for stop
 * signals. The process stop is done as a signal action for SIG_DFL.
 *
 * Returns true if the signal should be actually delivered, otherwise
 * it should be dropped.
 */
static bool prepare_signal(int sig, struct task_struct *p, bool force)
{
    struct signal_struct *signal = p->signal;
    struct task_struct *t;
    sigset_t flush;

    if (signal->flags & SIGNAL_GROUP_EXIT) {
        if (signal->core_state)
            return sig == SIGKILL;
        /*
         * The process is in the middle of dying, nothing to do.
         */
    } else if (sig_kernel_stop(sig)) {
#if 0
        /*
         * This is a stop signal.  Remove SIGCONT from all queues.
         */
        siginitset(&flush, sigmask(SIGCONT));
        flush_sigqueue_mask(&flush, &signal->shared_pending);
        for_each_thread(p, t)
            flush_sigqueue_mask(&flush, &t->pending);
#endif
        panic("%s: sig_kernel_stop!\n", __func__);
    } else if (sig == SIGCONT) {
        panic("%s: SIGCONT!\n", __func__);
    }

    return !sig_ignored(p, sig, force);
}

static inline bool legacy_queue(struct sigpending *signals, int sig)
{
    return (sig < SIGRTMIN) && sigismember(&signals->signal, sig);
}

static inline int is_si_special(const struct kernel_siginfo *info)
{
    return info <= SEND_SIG_PRIV;
}

static inline void print_dropped_signal(int sig)
{
    static DEFINE_RATELIMIT_STATE(ratelimit_state, 5 * HZ, 10);

    if (!print_fatal_signals)
        return;

    if (!__ratelimit(&ratelimit_state))
        return;

    pr_info("%s/%d: reached RLIMIT_SIGPENDING, dropped signal %d\n",
            current->comm, current->pid, sig);
}

/*
 * allocate a new signal queue record
 * - this may be called without locks if and only if t == current, otherwise an
 *   appropriate lock must be held to stop the target task from exiting
 */
static struct sigqueue *
__sigqueue_alloc(int sig, struct task_struct *t, gfp_t gfp_flags,
                 int override_rlimit, const unsigned int sigqueue_flags)
{
    struct sigqueue *q = NULL;
    struct ucounts *ucounts = NULL;
    long sigpending;

    /*
     * Protect access to @t credentials. This can go away when all
     * callers hold rcu read lock.
     *
     * NOTE! A pending signal will hold on to the user refcount,
     * and we get/put the refcount only when the sigpending count
     * changes from/to zero.
     */
    rcu_read_lock();
    ucounts = task_ucounts(t);
    sigpending = inc_rlimit_get_ucounts(ucounts,
                                        UCOUNT_RLIMIT_SIGPENDING);
    rcu_read_unlock();
    if (!sigpending)
        return NULL;

    if (override_rlimit ||
        likely(sigpending <= task_rlimit(t, RLIMIT_SIGPENDING))) {
        q = kmem_cache_alloc(sigqueue_cachep, gfp_flags);
    } else {
        print_dropped_signal(sig);
    }

    if (unlikely(q == NULL)) {
        dec_rlimit_put_ucounts(ucounts, UCOUNT_RLIMIT_SIGPENDING);
    } else {
        INIT_LIST_HEAD(&q->list);
        q->flags = sigqueue_flags;
        q->ucounts = ucounts;
    }
    return q;
}

/*
 * Test if P wants to take SIG.  After we've checked all threads with this,
 * it's equivalent to finding no threads not blocking SIG.  Any threads not
 * blocking SIG were ruled out because they are not running and already
 * have pending signals.  Such threads will dequeue from the shared queue
 * as soon as they're available, so putting the signal on the shared queue
 * will be equivalent to sending it to one such thread.
 */
static inline bool wants_signal(int sig, struct task_struct *p)
{
    if (sigismember(&p->blocked, sig))
        return false;

    if (p->flags & PF_EXITING)
        return false;

    if (sig == SIGKILL)
        return true;

    if (task_is_stopped_or_traced(p))
        return false;

    return task_curr(p) || !task_sigpending(p);
}

static void complete_signal(int sig, struct task_struct *p,
                            enum pid_type type)
{
    struct signal_struct *signal = p->signal;
    struct task_struct *t;

    /*
     * Now find a thread we can wake up to take the signal off the queue.
     *
     * If the main thread wants the signal, it gets first crack.
     * Probably the least surprising to the average bear.
     */
    if (wants_signal(sig, p))
        t = p;
    else if ((type == PIDTYPE_PID) || thread_group_empty(p))
        /*
         * There is just one thread and it does not need to be woken.
         * It will dequeue unblocked signals before it runs again.
         */
        return;
    else {
        panic("%s: 1!\n", __func__);
    }

    /*
     * Found a killable thread.  If the signal will be fatal,
     * then start taking the whole group down immediately.
     */
    if (sig_fatal(p, sig) &&
        (signal->core_state || !(signal->flags & SIGNAL_GROUP_EXIT)) &&
        !sigismember(&t->real_blocked, sig) &&
        (sig == SIGKILL || !p->ptrace)) {
        /*
         * This signal will be fatal to the whole group.
         */
        if (!sig_kernel_coredump(sig)) {
            panic("%s: 2!\n", __func__);
        }
    }

    /*
     * The signal is already in the shared-pending queue.
     * Tell the chosen thread to wake up and dequeue it.
     */
    signal_wake_up(t, sig == SIGKILL);
    return;
}

static int __send_signal(int sig, struct kernel_siginfo *info,
                         struct task_struct *t,
                         enum pid_type type, bool force)
{
    struct sigpending *pending;
    struct sigqueue *q;
    int override_rlimit;
    int ret = 0, result;

    assert_spin_locked(&t->sighand->siglock);

    result = TRACE_SIGNAL_IGNORED;
    if (!prepare_signal(sig, t, force))
        goto ret;

    pending = (type != PIDTYPE_PID) ?
        &t->signal->shared_pending : &t->pending;
    /*
     * Short-circuit ignored signals and support queuing
     * exactly one non-rt signal, so that we can get more
     * detailed information about the cause of the signal.
     */
    result = TRACE_SIGNAL_ALREADY_PENDING;
    if (legacy_queue(pending, sig))
        goto ret;

    result = TRACE_SIGNAL_DELIVERED;
    /*
     * Skip useless siginfo allocation for SIGKILL and kernel threads.
     */
    if ((sig == SIGKILL) || (t->flags & PF_KTHREAD))
        goto out_set;

    /*
     * Real-time signals must be queued if sent by sigqueue, or
     * some other real-time mechanism.  It is implementation
     * defined whether kill() does so.  We attempt to do so, on
     * the principle of least surprise, but since kill is not
     * allowed to fail with EAGAIN when low on memory we just
     * make sure at least one signal gets delivered and don't
     * pass on the info struct.
     */
    if (sig < SIGRTMIN)
        override_rlimit = (is_si_special(info) || info->si_code >= 0);
    else
        override_rlimit = 0;

    q = __sigqueue_alloc(sig, t, GFP_ATOMIC, override_rlimit, 0);

    if (q) {
        list_add_tail(&q->list, &pending->list);
        switch ((unsigned long) info) {
        case (unsigned long) SEND_SIG_NOINFO:
            clear_siginfo(&q->info);
            q->info.si_signo = sig;
            q->info.si_errno = 0;
            q->info.si_code = SI_USER;
            q->info.si_pid = task_tgid_nr_ns(current,
                                             task_active_pid_ns(t));
            rcu_read_lock();
            q->info.si_uid =
                from_kuid_munged(task_cred_xxx(t, user_ns),
                                 current_uid());
            rcu_read_unlock();
            break;
        case (unsigned long) SEND_SIG_PRIV:
            clear_siginfo(&q->info);
            q->info.si_signo = sig;
            q->info.si_errno = 0;
            q->info.si_code = SI_KERNEL;
            q->info.si_pid = 0;
            q->info.si_uid = 0;
            break;
        default:
            copy_siginfo(&q->info, info);
            break;
        }
    } else if (!is_si_special(info) &&
               sig >= SIGRTMIN && info->si_code != SI_USER) {
        /*
         * Queue overflow, abort.  We may abort if the
         * signal was rt and sent by user using something
         * other than kill().
         */
        result = TRACE_SIGNAL_OVERFLOW_FAIL;
        ret = -EAGAIN;
        goto ret;
    } else {
        panic("%s: else!\n", __func__);
    }

 out_set:
    signalfd_notify(t, sig);
    sigaddset(&pending->signal, sig);

    /* Let multiprocess signals appear after on-going forks */
    if (type > PIDTYPE_TGID) {
#if 0
        struct multiprocess_signals *delayed;
        hlist_for_each_entry(delayed, &t->signal->multiprocess, node) {
            sigset_t *signal = &delayed->signal;
            /* Can't queue both a stop and a continue signal */
            if (sig == SIGCONT)
                sigdelsetmask(signal, SIG_KERNEL_STOP_MASK);
            else if (sig_kernel_stop(sig))
                sigdelset(signal, SIGCONT);
            sigaddset(signal, sig);
        }
#endif
        panic("%s: PIDTYPE_TGID!\n", __func__);
    }

    complete_signal(sig, t, type);

 ret:
    return ret;
}

static int send_signal(int sig, struct kernel_siginfo *info,
                       struct task_struct *t, enum pid_type type)
{
    /* Should SIGKILL or SIGSTOP be received by a pid namespace init? */
    bool force = false;

    if (info == SEND_SIG_NOINFO) {
        /* Force if sent from an ancestor pid namespace */
        force = !task_pid_nr_ns(current, task_active_pid_ns(t));
    } else if (info == SEND_SIG_PRIV) {
        /* Don't ignore kernel generated signals */
        force = true;
    } else if (has_si_pid_and_uid(info)) {
        panic("%s: has_si_pid_and_uid!\n", __func__);
    }
    return __send_signal(sig, info, t, type, force);
}

/*
 * Force a signal that the process can't ignore: if necessary
 * we unblock the signal and change any SIG_IGN to SIG_DFL.
 *
 * Note: If we unblock the signal, we always reset it to SIG_DFL,
 * since we do not want to have a signal handler that was blocked
 * be invoked when user space had explicitly blocked it.
 *
 * We don't want to have recursive SIGSEGV's etc, for example,
 * that is why we also clear SIGNAL_UNKILLABLE.
 */
static int
force_sig_info_to_task(struct kernel_siginfo *info,
                       struct task_struct *t,
                       enum sig_handler handler)
{
    unsigned long int flags;
    int ret, blocked, ignored;
    struct k_sigaction *action;
    int sig = info->si_signo;

    spin_lock_irqsave(&t->sighand->siglock, flags);
    action = &t->sighand->action[sig-1];
    ignored = action->sa.sa_handler == SIG_IGN;
    blocked = sigismember(&t->blocked, sig);
    if (blocked || ignored || (handler != HANDLER_CURRENT)) {
        action->sa.sa_handler = SIG_DFL;
        if (handler == HANDLER_EXIT)
            action->sa.sa_flags |= SA_IMMUTABLE;
        if (blocked) {
            sigdelset(&t->blocked, sig);
            recalc_sigpending_and_wake(t);
        }
    }
    /*
     * Don't clear SIGNAL_UNKILLABLE for traced tasks, users won't expect
     * debugging to leave init killable. But HANDLER_EXIT is always fatal.
     */
    if (action->sa.sa_handler == SIG_DFL &&
        (!t->ptrace || (handler == HANDLER_EXIT)))
        t->signal->flags &= ~SIGNAL_UNKILLABLE;
    ret = send_signal(sig, info, t, PIDTYPE_PID);
    spin_unlock_irqrestore(&t->sighand->siglock, flags);

    return ret;
}

int force_sig_fault_to_task(int sig, int code, void __user *addr,
                            struct task_struct *t)
{
    struct kernel_siginfo info;

    clear_siginfo(&info);
    info.si_signo = sig;
    info.si_errno = 0;
    info.si_code  = code;
    info.si_addr  = addr;
    return force_sig_info_to_task(&info, t, HANDLER_CURRENT);
}

int force_sig_fault(int sig, int code, void __user *addr)
{
    return force_sig_fault_to_task(sig, code, addr, current);
}

/*
 * Tell a process that it has a new active signal..
 *
 * NOTE! we rely on the previous spin_lock to
 * lock interrupts for us! We can only be called with
 * "siglock" held, and the local interrupt must
 * have been disabled when that got acquired!
 *
 * No need to set need_resched since signal event passing
 * goes through ->blocked
 */
void signal_wake_up_state(struct task_struct *t, unsigned int state)
{
    set_tsk_thread_flag(t, TIF_SIGPENDING);
    /*
     * TASK_WAKEKILL also means wake it up in the stopped/traced/killable
     * case. We don't check t->state here because there is a race with it
     * executing another processor and just now entering stopped state.
     * By using wake_up_state, we ensure the process will wake up and
     * handle its death signal.
     */
    if (!wake_up_state(t, state | TASK_INTERRUPTIBLE))
        kick_process(t);
}

static void hide_si_addr_tag_bits(struct ksignal *ksig)
{
    panic("%s: END!\n", __func__);
}

/**
 * do_signal_stop - handle group stop for SIGSTOP and other stop signals
 * @signr: signr causing group stop if initiating
 *
 * If %JOBCTL_STOP_PENDING is not set yet, initiate group stop with @signr
 * and participate in it.  If already set, participate in the existing
 * group stop.  If participated in a group stop (and thus slept), %true is
 * returned with siglock released.
 *
 * If ptraced, this function doesn't handle stop itself.  Instead,
 * %JOBCTL_TRAP_STOP is scheduled and %false is returned with siglock
 * untouched.  The caller must ensure that INTERRUPT trap handling takes
 * places afterwards.
 *
 * CONTEXT:
 * Must be called with @current->sighand->siglock held, which is released
 * on %true return.
 *
 * RETURNS:
 * %false if group stop is already cancelled or ptrace trap is scheduled.
 * %true if participated in group stop.
 */
static bool do_signal_stop(int signr)
    __releases(&current->sighand->siglock)
{
    panic("%s: END!\n", __func__);
}

void recalc_sigpending(void)
{
    if (!recalc_sigpending_tsk(current))
        clear_thread_flag(TIF_SIGPENDING);

}
EXPORT_SYMBOL(recalc_sigpending);

static void __sigqueue_free(struct sigqueue *q)
{
    if (q->flags & SIGQUEUE_PREALLOC)
        return;
    if (q->ucounts) {
        dec_rlimit_put_ucounts(q->ucounts, UCOUNT_RLIMIT_SIGPENDING);
        q->ucounts = NULL;
    }
    kmem_cache_free(sigqueue_cachep, q);
}

/* Given the mask, find the first available signal that should be serviced. */

#define SYNCHRONOUS_MASK \
    (sigmask(SIGSEGV) | sigmask(SIGBUS) | sigmask(SIGILL) | \
     sigmask(SIGTRAP) | sigmask(SIGFPE) | sigmask(SIGSYS))

static int dequeue_synchronous_signal(kernel_siginfo_t *info)
{
    struct task_struct *tsk = current;
    struct sigpending *pending = &tsk->pending;
    struct sigqueue *q, *sync = NULL;

    /*
     * Might a synchronous signal be in the queue?
     */
    if (!((pending->signal.sig[0] & ~tsk->blocked.sig[0]) &
          SYNCHRONOUS_MASK))
        return 0;

    /*
     * Return the first synchronous signal in the queue.
     */
    list_for_each_entry(q, &pending->list, list) {
        /* Synchronous signals have a positive si_code */
        if ((q->info.si_code > SI_USER) &&
            (sigmask(q->info.si_signo) & SYNCHRONOUS_MASK)) {
            sync = q;
            goto next;
        }
    }
    return 0;

 next:
    /*
     * Check if there is another siginfo for the same signal.
     */
    list_for_each_entry_continue(q, &pending->list, list) {
        if (q->info.si_signo == sync->info.si_signo)
            goto still_pending;
    }

    sigdelset(&pending->signal, sync->info.si_signo);
    recalc_sigpending();

 still_pending:
    list_del_init(&sync->list);
    copy_siginfo(info, &sync->info);
    __sigqueue_free(sync);
    return info->si_signo;
}

/*
 * Dequeue a signal and return the element to the caller, which is
 * expected to free it.
 *
 * All callers have to hold the siglock.
 */
int dequeue_signal(struct task_struct *tsk, sigset_t *mask,
                   kernel_siginfo_t *info, enum pid_type *type)
{
    panic("%s: END!\n", __func__);
}

static int ptrace_signal(int signr, kernel_siginfo_t *info,
                         enum pid_type type)
{
    panic("%s: END!\n", __func__);
}

static void print_fatal_signal(int signr)
{
    struct pt_regs *regs = signal_pt_regs();
    pr_info("potentially unexpected fatal signal %d.\n", signr);

    preempt_disable();
    show_regs(regs);
    preempt_enable();
}

bool get_signal(struct ksignal *ksig)
{
    struct sighand_struct *sighand = current->sighand;
    struct signal_struct *signal = current->signal;
    int signr;

    clear_notify_signal();
    if (unlikely(task_work_pending(current)))
        task_work_run();

    if (!task_sigpending(current))
        return false;

 relock:
    spin_lock_irq(&sighand->siglock);

    /*
     * Every stopped thread goes here after wakeup. Check to see if
     * we should notify the parent, prepare_signal(SIGCONT) encodes
     * the CLD_ si_code into SIGNAL_CLD_MASK bits.
     */
    if (unlikely(signal->flags & SIGNAL_CLD_MASK)) {
        panic("%s: 1!\n", __func__);
    }

    for (;;) {
        struct k_sigaction *ka;
        enum pid_type type;

        /* Has this task already been marked for death? */
        if ((signal->flags & SIGNAL_GROUP_EXIT) ||
            signal->group_exec_task) {
#if 0
            ksig->info.si_signo = signr = SIGKILL;
            sigdelset(&current->pending.signal, SIGKILL);
            recalc_sigpending();
            goto fatal;
#endif
            panic("%s: SIGNAL_GROUP_EXIT!\n", __func__);
        }

        if (unlikely(current->jobctl & JOBCTL_STOP_PENDING) &&
            do_signal_stop(0))
            goto relock;

        if (unlikely(current->jobctl &
                     (JOBCTL_TRAP_MASK | JOBCTL_TRAP_FREEZE))) {
#if 0
            if (current->jobctl & JOBCTL_TRAP_MASK) {
                do_jobctl_trap();
                spin_unlock_irq(&sighand->siglock);
            } else if (current->jobctl & JOBCTL_TRAP_FREEZE)
                do_freezer_trap();

            goto relock;
#endif
            panic("%s: 1.5!\n", __func__);
        }

        /*
         * If the task is leaving the frozen state, let's update
         * cgroup counters and reset the frozen bit.
         */
        if (unlikely(cgroup_task_frozen(current))) {
#if 0
            spin_unlock_irq(&sighand->siglock);
            cgroup_leave_frozen(false);
            goto relock;
#endif
            panic("%s: 1.6!\n", __func__);
        }

        /*
         * Signals generated by the execution of an instruction
         * need to be delivered before any other pending signals
         * so that the instruction pointer in the signal stack
         * frame points to the faulting instruction.
         */
        type = PIDTYPE_PID;
        signr = dequeue_synchronous_signal(&ksig->info);
        if (!signr)
            signr = dequeue_signal(current, &current->blocked,
                                   &ksig->info, &type);

        if (!signr)
            break; /* will return 0 */

        if (unlikely(current->ptrace) && (signr != SIGKILL) &&
            !(sighand->action[signr -1].sa.sa_flags & SA_IMMUTABLE)) {
            signr = ptrace_signal(signr, &ksig->info, type);
            if (!signr)
                continue;
        }

        ka = &sighand->action[signr-1];

        if (ka->sa.sa_handler == SIG_IGN) /* Do nothing.  */
            continue;
        if (ka->sa.sa_handler != SIG_DFL) {
            /* Run the handler.  */
            ksig->ka = *ka;

            if (ka->sa.sa_flags & SA_ONESHOT)
                ka->sa.sa_handler = SIG_DFL;

            break; /* will return non-zero "signr" value */
        }

        /*
         * Now we are doing the default action for this signal.
         */
        if (sig_kernel_ignore(signr)) /* Default is nothing. */
            continue;

        /*
         * Global init gets no signals it doesn't want.
         * Container-init gets no signals it doesn't want from same
         * container.
         *
         * Note that if global/container-init sees a sig_kernel_only()
         * signal here, the signal must have been generated internally
         * or must have come from an ancestor namespace. In either
         * case, the signal cannot be dropped.
         */
        if (unlikely(signal->flags & SIGNAL_UNKILLABLE) &&
            !sig_kernel_only(signr))
            continue;

        if (sig_kernel_stop(signr)) {
            panic("%s: sig_kernel_stop!\n", __func__);
        }

     fatal:
        spin_unlock_irq(&sighand->siglock);
        if (unlikely(cgroup_task_frozen(current)))
            cgroup_leave_frozen(true);

        /*
         * Anything else is fatal, maybe with a core dump.
         */
        current->flags |= PF_SIGNALED;

        if (sig_kernel_coredump(signr)) {
            if (print_fatal_signals)
                print_fatal_signal(ksig->info.si_signo);

            /*
             * If it was able to dump core, this kills all
             * other threads in the group and synchronizes with
             * their demise.  If we lost the race with another
             * thread getting here, it set group_exit_code
             * first and our do_group_exit call below will use
             * that value and ignore the one we pass it.
             */
            //do_coredump(&ksig->info);
        }


        /*
         * PF_IO_WORKER threads will catch and exit on fatal signals
         * themselves. They have cleanup that must be performed, so
         * we cannot call do_exit() on their behalf.
         */
        if (current->flags & PF_IO_WORKER)
            goto out;

        /*
         * Death signals, no core dump.
         */
        do_group_exit(ksig->info.si_signo);
        /* NOTREACHED */
    }
    spin_unlock_irq(&sighand->siglock);
out:
    ksig->sig = signr;

    if (!(ksig->ka.sa.sa_flags & SA_EXPOSE_TAGBITS))
        hide_si_addr_tag_bits(ksig);

    panic("%s: END!\n", __func__);
    return ksig->sig > 0;
}

/**
 * task_clear_jobctl_trapping - clear jobctl trapping bit
 * @task: target task
 *
 * If JOBCTL_TRAPPING is set, a ptracer is waiting for us to enter TRACED.
 * Clear it and wake up the ptracer.  Note that we don't need any further
 * locking.  @task->siglock guarantees that @task->parent points to the
 * ptracer.
 *
 * CONTEXT:
 * Must be called with @task->sighand->siglock held.
 */
void task_clear_jobctl_trapping(struct task_struct *task)
{
    if (unlikely(task->jobctl & JOBCTL_TRAPPING)) {
        task->jobctl &= ~JOBCTL_TRAPPING;
        smp_mb();   /* advised by wake_up_bit() */
        wake_up_bit(&task->jobctl, JOBCTL_TRAPPING_BIT);
    }
}

/**
 * task_clear_jobctl_pending - clear jobctl pending bits
 * @task: target task
 * @mask: pending bits to clear
 *
 * Clear @mask from @task->jobctl.  @mask must be subset of
 * %JOBCTL_PENDING_MASK.  If %JOBCTL_STOP_PENDING is being cleared, other
 * STOP bits are cleared together.
 *
 * If clearing of @mask leaves no stop or trap pending, this function calls
 * task_clear_jobctl_trapping().
 *
 * CONTEXT:
 * Must be called with @task->sighand->siglock held.
 */
void task_clear_jobctl_pending(struct task_struct *task,
                               unsigned long mask)
{
    BUG_ON(mask & ~JOBCTL_PENDING_MASK);

    if (mask & JOBCTL_STOP_PENDING)
        mask |= JOBCTL_STOP_CONSUME | JOBCTL_STOP_DEQUEUED;

    task->jobctl &= ~mask;

    if (!(task->jobctl & JOBCTL_PENDING_MASK))
        task_clear_jobctl_trapping(task);
}

/*
 * Nuke all other threads in the group.
 */
int zap_other_threads(struct task_struct *p)
{
    struct task_struct *t = p;
    int count = 0;

    p->signal->group_stop_count = 0;

    while_each_thread(p, t) {
        task_clear_jobctl_pending(t, JOBCTL_PENDING_MASK);
        count++;

        /* Don't bother with already dead threads */
        if (t->exit_state)
            continue;
        sigaddset(&t->pending.signal, SIGKILL);
        signal_wake_up(t, 1);
    }

    return count;
}

static inline void siginfo_buildtime_checks(void)
{
    BUILD_BUG_ON(sizeof(struct siginfo) != SI_MAX_SIZE);

    /* Verify the offsets in the two siginfos match */
#define CHECK_OFFSET(field) \
    BUILD_BUG_ON(offsetof(siginfo_t, field) != \
                 offsetof(kernel_siginfo_t, field))

    /* kill */
    CHECK_OFFSET(si_pid);
    CHECK_OFFSET(si_uid);

    /* timer */
    CHECK_OFFSET(si_tid);
    CHECK_OFFSET(si_overrun);
    CHECK_OFFSET(si_value);

    /* rt */
    CHECK_OFFSET(si_pid);
    CHECK_OFFSET(si_uid);
    CHECK_OFFSET(si_value);

    /* sigchld */
    CHECK_OFFSET(si_pid);
    CHECK_OFFSET(si_uid);
    CHECK_OFFSET(si_status);
    CHECK_OFFSET(si_utime);
    CHECK_OFFSET(si_stime);

    /* sigfault */
    CHECK_OFFSET(si_addr);
    CHECK_OFFSET(si_trapno);
    CHECK_OFFSET(si_addr_lsb);
    CHECK_OFFSET(si_lower);
    CHECK_OFFSET(si_upper);
    CHECK_OFFSET(si_pkey);
    CHECK_OFFSET(si_perf_data);
    CHECK_OFFSET(si_perf_type);

    /* sigpoll */
    CHECK_OFFSET(si_band);
    CHECK_OFFSET(si_fd);

    /* sigsys */
    CHECK_OFFSET(si_call_addr);
    CHECK_OFFSET(si_syscall);
    CHECK_OFFSET(si_arch);
#undef CHECK_OFFSET

    /* usb asyncio */
    BUILD_BUG_ON(offsetof(struct siginfo, si_pid) !=
                 offsetof(struct siginfo, si_addr));
    if (sizeof(int) == sizeof(void __user *)) {
        BUILD_BUG_ON(sizeof_field(struct siginfo, si_pid) !=
                     sizeof(void __user *));
    } else {
        BUILD_BUG_ON((sizeof_field(struct siginfo, si_pid) +
                      sizeof_field(struct siginfo, si_uid)) !=
                     sizeof(void __user *));
        BUILD_BUG_ON(offsetofend(struct siginfo, si_pid) !=
                     offsetof(struct siginfo, si_uid));
    }

    BUILD_BUG_ON(offsetof(struct compat_siginfo, si_pid) !=
                 offsetof(struct compat_siginfo, si_addr));
    BUILD_BUG_ON(sizeof_field(struct compat_siginfo, si_pid) !=
                 sizeof(compat_uptr_t));
    BUILD_BUG_ON(sizeof_field(struct compat_siginfo, si_pid) !=
                 sizeof_field(struct siginfo, si_pid));
}

void __init signals_init(void)
{
    siginfo_buildtime_checks();

    sigqueue_cachep = KMEM_CACHE(sigqueue, SLAB_PANIC | SLAB_ACCOUNT);
}

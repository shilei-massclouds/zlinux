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
#include <linux/syscalls.h>
#include <linux/ptrace.h>
#endif
#include <linux/signal.h>
//#include <linux/signalfd.h>
#include <linux/ratelimit.h>
#if 0
#include <linux/task_work.h>
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
#include <linux/cgroup.h>
#include <linux/audit.h>
#endif

#include <asm/param.h>
#include <linux/uaccess.h>
#if 0
#include <asm/unistd.h>
#include <asm/siginfo.h>
#endif
#include <asm/cacheflush.h>
//#include <asm/syscall.h>    /* for syscall_get_* */

/*
 * SLAB caches for signal bits.
 */

static struct kmem_cache *sigqueue_cachep;

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

int force_sig_fault_to_task(int sig, int code, void __user *addr,
                            struct task_struct *t)
{
    panic("%s: END!\n", __func__);
}

int force_sig_fault(int sig, int code, void __user *addr)
{
    return force_sig_fault_to_task(sig, code, addr, current);
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

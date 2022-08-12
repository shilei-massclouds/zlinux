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
#if 0
#include <linux/proc_fs.h>
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

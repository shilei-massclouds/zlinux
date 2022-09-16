/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PTRACE_H
#define _LINUX_PTRACE_H

#include <linux/compiler.h>     /* For unlikely.  */
#include <linux/sched.h>        /* For struct task_struct.  */
#include <linux/sched/signal.h> /* For send_sig(), same_thread_group(), etc. */
#include <linux/err.h>          /* for IS_ERR_VALUE */
#include <linux/bug.h>          /* For BUG_ON.  */
#include <linux/pid_namespace.h>    /* For task_active_pid_ns.  */
//#include <uapi/linux/ptrace.h>
//#include <linux/seccomp.h>

#ifndef current_pt_regs
#define current_pt_regs() task_pt_regs(current)
#endif

/*
 * unlike current_pt_regs(), this one is equal to task_pt_regs(current)
 * on *all* architectures; the only reason to have a per-arch definition
 * is optimisation.
 */
#ifndef signal_pt_regs
#define signal_pt_regs() task_pt_regs(current)
#endif

#endif /* _LINUX_PTRACE_H */

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2009 Sunplus Core Technology Co., Ltd.
 *  Chen Liqin <liqin.chen@sunplusct.com>
 *  Lennox Wu <lennox.wu@sunplusct.com>
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#if 0
#include <linux/tick.h>
#include <linux/ptrace.h>
#endif
#include <linux/uaccess.h>

//#include <asm/unistd.h>
#include <asm/processor.h>
#include <asm/csr.h>
//#include <asm/stacktrace.h>
#include <asm/string.h>
#include <asm/switch_to.h>
#include <asm/thread_info.h>
//#include <asm/cpuidle.h>

register unsigned long gp_in_global __asm__("gp");

#ifdef CONFIG_STACKPROTECTOR
#include <linux/stackprotector.h>
unsigned long __stack_chk_guard __read_mostly;
EXPORT_SYMBOL(__stack_chk_guard);
#endif

extern asmlinkage void ret_from_kernel_thread(void);

int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
#if 0
    fstate_save(src, task_pt_regs(src));
#endif
    *dst = *src;
    return 0;
}

int copy_thread(unsigned long clone_flags, unsigned long usp, unsigned long arg,
                struct task_struct *p, unsigned long tls)
{
    struct pt_regs *childregs = task_pt_regs(p);

    /* p->thread holds context to be restored by __switch_to() */
    if (unlikely(p->flags & (PF_KTHREAD | PF_IO_WORKER))) {
        /* Kernel thread */
        memset(childregs, 0, sizeof(struct pt_regs));
        childregs->gp = gp_in_global;
        /* Supervisor/Machine, irqs on: */
        childregs->status = SR_PP | SR_PIE;

        p->thread.ra = (unsigned long)ret_from_kernel_thread;
        p->thread.s[0] = usp; /* fn */
        p->thread.s[1] = arg;
    } else {
        panic("%s: NO implementation!\n", __func__);
#if 0
        *childregs = *(current_pt_regs());
        if (usp) /* User fork */
            childregs->sp = usp;
        if (clone_flags & CLONE_SETTLS)
            childregs->tp = tls;
        childregs->a0 = 0; /* Return value of fork() */
        p->thread.ra = (unsigned long)ret_from_fork;
#endif
    }
    p->thread.sp = (unsigned long)childregs; /* kernel sp */
    return 0;
}

void flush_thread(void)
{
    /*
     * Reset FPU state and context
     *  frm: round to nearest, ties to even (IEEE default)
     *  fflags: accrued exceptions cleared
     */
    fstate_off(current, task_pt_regs(current));
    memset(&current->thread.fstate, 0, sizeof(current->thread.fstate));
}

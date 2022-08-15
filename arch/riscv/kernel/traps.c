// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/signal.h>
#include <linux/signal.h>
//#include <linux/kdebug.h>
#include <linux/uaccess.h>
//#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/irq.h>

#include <asm/asm-prototypes.h>
#include <asm/bug.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/csr.h>

int show_unhandled_signals = 1;

void do_trap(struct pt_regs *regs, int signo, int code, unsigned long addr)
{
    struct task_struct *tsk = current;

#if 0
    if (show_unhandled_signals && unhandled_signal(tsk, signo)
        && printk_ratelimit()) {
        pr_info("%s[%d]: unhandled signal %d code 0x%x at 0x" REG_FMT,
            tsk->comm, task_pid_nr(tsk), signo, code, addr);
        print_vma_addr(KERN_CONT " in ", instruction_pointer(regs));
        pr_cont("\n");
        __show_regs(regs);
    }
#endif

    force_sig_fault(signo, code, (void __user *)addr);
}

static void do_trap_error(struct pt_regs *regs, int signo, int code,
                          unsigned long addr, const char *str)
{
    current->thread.bad_cause = regs->cause;

    if (user_mode(regs)) {
        do_trap(regs, signo, code, addr);
    } else {
#if 0
        if (!fixup_exception(regs))
            die(regs, str);
#endif
        panic("%s: NOT user_mode!\n", __func__);
    }
}

#define __trap_section

#define DO_ERROR_INFO(name, signo, code, str)               \
asmlinkage __visible __trap_section void name(struct pt_regs *regs) \
{                                   \
    do_trap_error(regs, signo, code, regs->epc, "Oops - " str); \
}

DO_ERROR_INFO(do_trap_unknown,
              SIGILL, ILL_ILLTRP, "unknown exception");
DO_ERROR_INFO(do_trap_insn_misaligned,
              SIGBUS, BUS_ADRALN, "instruction address misaligned");
DO_ERROR_INFO(do_trap_insn_fault,
              SIGSEGV, SEGV_ACCERR, "instruction access fault");
DO_ERROR_INFO(do_trap_insn_illegal,
              SIGILL, ILL_ILLOPC, "illegal instruction");
DO_ERROR_INFO(do_trap_load_fault,
              SIGSEGV, SEGV_ACCERR, "load access fault");
DO_ERROR_INFO(do_trap_load_misaligned,
              SIGBUS, BUS_ADRALN, "Oops - load address misaligned");
DO_ERROR_INFO(do_trap_store_misaligned,
              SIGBUS, BUS_ADRALN, "Oops - store (or AMO) address misaligned");
DO_ERROR_INFO(do_trap_store_fault,
              SIGSEGV, SEGV_ACCERR, "store (or AMO) access fault");
DO_ERROR_INFO(do_trap_ecall_u,
              SIGILL, ILL_ILLTRP, "environment call from U-mode");
DO_ERROR_INFO(do_trap_ecall_s,
              SIGILL, ILL_ILLTRP, "environment call from S-mode");
DO_ERROR_INFO(do_trap_ecall_m,
              SIGILL, ILL_ILLTRP, "environment call from M-mode");

asmlinkage __visible __trap_section void do_trap_break(struct pt_regs *regs)
{
    current->thread.bad_cause = regs->cause;

#if 0
    if (user_mode(regs))
        force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->epc);
    else if (report_bug(regs->epc, regs) == BUG_TRAP_TYPE_WARN)
        regs->epc += get_break_insn_length(regs->epc);
    else
        die(regs, "Kernel BUG");
#endif
    panic("%s: END!\n", __func__);
}

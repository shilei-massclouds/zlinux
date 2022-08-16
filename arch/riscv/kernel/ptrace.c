// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2010 Tilera Corporation. All Rights Reserved.
 * Copyright 2015 Regents of the University of California
 * Copyright 2017 SiFive
 *
 * Copied from arch/tile/kernel/ptrace.c
 */

#include <asm/ptrace.h>
//#include <asm/syscall.h>
#include <asm/thread_info.h>
#include <asm/switch_to.h>
//#include <linux/audit.h>
#include <linux/ptrace.h>
#include <linux/elf.h>
//#include <linux/regset.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>

#define CREATE_TRACE_POINTS
//#include <trace/events/syscalls.h>

/*
 * Allows PTRACE_SYSCALL to work.  These are called from entry.S in
 * {handle,ret_from}_syscall.
 */
__visible int do_syscall_trace_enter(struct pt_regs *regs)
{
    panic("%s: END!\n", __func__);
}

__visible void do_syscall_trace_exit(struct pt_regs *regs)
{
    panic("%s: END!\n", __func__);
}

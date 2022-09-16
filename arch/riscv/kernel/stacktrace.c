// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2008 ARM Limited
 * Copyright (C) 2014 Regents of the University of California
 */

#include <linux/export.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>
#include <linux/ftrace.h>

#include <asm/stacktrace.h>

noinline void dump_backtrace(struct pt_regs *regs,
                             struct task_struct *task,
                             const char *loglvl)
{
    //walk_stackframe(task, regs, print_trace_address, (void *)loglvl);
    panic("%s: NO implementation!\n", __func__);
}

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kernel/stop_machine.c
 *
 * Copyright (C) 2008, 2005 IBM Corporation.
 * Copyright (C) 2008, 2005 Rusty Russell rusty@rustcorp.com.au
 * Copyright (C) 2010       SUSE Linux Products GmbH
 * Copyright (C) 2010       Tejun Heo <tj@kernel.org>
 */
#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/cpu.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/stop_machine.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/smpboot.h>
#include <linux/atomic.h>
//#include <linux/nmi.h>
#include <linux/sched/wake_q.h>

/**
 * stop_one_cpu - stop a cpu
 * @cpu: cpu to stop
 * @fn: function to execute
 * @arg: argument to @fn
 *
 * Execute @fn(@arg) on @cpu.  @fn is run in a process context with
 * the highest priority preempting any task on the cpu and
 * monopolizing it.  This function returns after the execution is
 * complete.
 *
 * This function doesn't guarantee @cpu stays online till @fn
 * completes.  If @cpu goes down in the middle, execution may happen
 * partially or fully on different cpus.  @fn should either be ready
 * for that or the caller should ensure that @cpu stays online until
 * this function completes.
 *
 * CONTEXT:
 * Might sleep.
 *
 * RETURNS:
 * -ENOENT if @fn(@arg) was not executed because @cpu was offline;
 * otherwise, the return value of @fn.
 */
int stop_one_cpu(unsigned int cpu, cpu_stop_fn_t fn, void *arg)
{
    panic("%s: NO implementation!\n", __func__);
}

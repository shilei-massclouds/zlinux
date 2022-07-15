// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/softirq.c
 *
 *  Copyright (C) 1992 Linus Torvalds
 *
 *  Rewritten. Old one was good in 2.2, but in 2.3 it was immoral. --ANK (990903)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/export.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/local_lock.h>
#include <linux/mm.h>
#if 0
#include <linux/notifier.h>
#include <linux/freezer.h>
#include <linux/ftrace.h>
#include <linux/smpboot.h>
#endif
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/smp.h>
#if 0
#include <linux/tick.h>
#include <linux/wait_bit.h>
#endif
#include <linux/irq.h>

#if 0
#include <asm/softirq_stack.h>
#endif

unsigned int __weak arch_dynirq_lower_bound(unsigned int from)
{
    return from;
}

void __local_bh_enable_ip(unsigned long ip, unsigned int cnt)
{
    panic("%s: END!\n", __func__);
}

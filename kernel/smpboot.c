// SPDX-License-Identifier: GPL-2.0-only
/*
 * Common SMP CPU bringup/teardown functions
 */
#include <linux/cpu.h>
#include <linux/err.h>
#include <linux/smp.h>
//#include <linux/delay.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/kthread.h>
//#include <linux/smpboot.h>

#include "smpboot.h"

/*
 * For the hotplug case we keep the task structs around and reuse
 * them.
 */
static DEFINE_PER_CPU(struct task_struct *, idle_threads);

void __init idle_thread_set_boot_cpu(void)
{
    per_cpu(idle_threads, smp_processor_id()) = current;
}

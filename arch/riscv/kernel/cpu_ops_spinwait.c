// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 */

#include <linux/errno.h>
#include <linux/of.h>
#include <linux/string.h>
#include <linux/sched/task_stack.h>
//#include <asm/cpu_ops.h>
#include <asm/sbi.h>
#include <asm/smp.h>

void *__cpu_spinwait_stack_pointer[NR_CPUS] __section(".data");
void *__cpu_spinwait_task_pointer[NR_CPUS] __section(".data");

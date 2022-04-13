// SPDX-License-Identifier: GPL-2.0-only

#include <linux/mm.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/threads.h>

void *__cpu_up_stack_pointer[NR_CPUS] __section(.data);
void *__cpu_up_task_pointer[NR_CPUS] __section(.data);

// SPDX-License-Identifier: GPL-2.0-only

#define GENERATING_ASM_OFFSETS

#include <linux/stddef.h>
#include <linux/kbuild.h>
#include <linux/sched.h>

void asm_offsets(void)
{
    OFFSET(TASK_TI_CPU, task_struct, thread_info.cpu);
}

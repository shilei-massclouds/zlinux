/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_HEAD_H
#define __ASM_HEAD_H

#include <linux/linkage.h>
#include <linux/init.h>

extern atomic_t hart_lottery;

asmlinkage void __init setup_vm(uintptr_t dtb_pa);

void __init parse_dtb(void);

extern void *__cpu_spinwait_stack_pointer[];
extern void *__cpu_spinwait_task_pointer[];

#endif /* __ASM_HEAD_H */

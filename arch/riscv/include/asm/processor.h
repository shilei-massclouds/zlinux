/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_PROCESSOR_H
#define _ASM_RISCV_PROCESSOR_H

#include <linux/const.h>

#include <vdso/processor.h>

#include <asm/ptrace.h>

#ifndef __ASSEMBLY__

struct task_struct;
struct pt_regs;

/* CPU-specific state of a task */
struct thread_struct {
    /* Callee-saved registers */
    unsigned long ra;
    unsigned long sp;   /* Kernel mode stack */
    unsigned long s[12];    /* s[0]: frame pointer */
    struct __riscv_d_ext_state fstate;
    unsigned long bad_cause;
};

struct device_node;
int riscv_of_processor_hartid(struct device_node *node);

extern int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src);

/* Whitelist the fstate from the task_struct for hardened usercopy */
static inline void arch_thread_struct_whitelist(unsigned long *offset,
                        unsigned long *size)
{
    *offset = offsetof(struct thread_struct, fstate);
    *size = sizeof_field(struct thread_struct, fstate);
}

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_RISCV_PROCESSOR_H */

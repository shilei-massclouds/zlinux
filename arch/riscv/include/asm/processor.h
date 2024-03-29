/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_PROCESSOR_H
#define _ASM_RISCV_PROCESSOR_H

#include <linux/const.h>

#include <vdso/processor.h>

#include <asm/ptrace.h>

/*
 * This decides where the kernel will search for a free chunk of vm
 * space during mmap's.
 */
#define TASK_UNMAPPED_BASE  PAGE_ALIGN(TASK_SIZE / 3)

#define STACK_TOP       TASK_SIZE
#define STACK_TOP_MAX   STACK_TOP
#define STACK_ALIGN     16

#ifndef __ASSEMBLY__

struct task_struct;
struct pt_regs;

/* CPU-specific state of a task */
struct thread_struct {
    /* Callee-saved registers */
    unsigned long ra;
    unsigned long sp;       /* Kernel mode stack */
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

#define task_pt_regs(tsk) \
    ((struct pt_regs *)(task_stack_page(tsk) + THREAD_SIZE \
                        - ALIGN(sizeof(struct pt_regs), STACK_ALIGN)))

int riscv_of_parent_hartid(struct device_node *node);

/* Do necessary setup to start up a newly executed thread. */
extern void start_thread(struct pt_regs *regs, unsigned long pc,
                         unsigned long sp);

#define INIT_THREAD {   \
    .sp = sizeof(init_stack) + (long)&init_stack,   \
}

extern void riscv_fill_hwcap(void);

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_RISCV_PROCESSOR_H */

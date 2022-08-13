/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_SWITCH_TO_H
#define _ASM_RISCV_SWITCH_TO_H

#include <linux/jump_label.h>
#include <linux/sched/task_stack.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/csr.h>

extern struct task_struct *
__switch_to(struct task_struct *, struct task_struct *);

#define switch_to(prev, next, last)         \
do {                                        \
    struct task_struct *__prev = (prev);    \
    struct task_struct *__next = (next);    \
    ((last) = __switch_to(__prev, __next)); \
} while (0)

static inline void fstate_off(struct task_struct *task,
                              struct pt_regs *regs)
{
    regs->status = (regs->status & ~SR_FS) | SR_FS_OFF;
}

#endif /* _ASM_RISCV_SWITCH_TO_H */

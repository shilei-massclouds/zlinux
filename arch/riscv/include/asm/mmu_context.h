/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#ifndef _ASM_RISCV_MMU_CONTEXT_H
#define _ASM_RISCV_MMU_CONTEXT_H

#include <linux/mm_types.h>
//#include <asm-generic/mm_hooks.h>

#include <linux/mm.h>
#include <linux/sched.h>

#define init_new_context init_new_context
static inline int init_new_context(struct task_struct *tsk,
                                   struct mm_struct *mm)
{
    atomic_long_set(&mm->context.id, 0);
    return 0;
}

//#include <asm-generic/mmu_context.h>

#endif /* _ASM_RISCV_MMU_CONTEXT_H */

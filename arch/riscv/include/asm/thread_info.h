/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_THREAD_INFO_H
#define _ASM_RISCV_THREAD_INFO_H

#include <asm/page.h>
#include <linux/const.h>

#define THREAD_SIZE_ORDER (2)
#define THREAD_SIZE (PAGE_SIZE << THREAD_SIZE_ORDER)

#ifndef __ASSEMBLY__

#include <asm/processor.h>
#include <asm/csr.h>

typedef struct {
    unsigned long seg;
} mm_segment_t;

/*
 * low level task data that entry.S needs immediate access to
 * - this struct should fit entirely inside of one cache line
 * - if the members of this struct changes, the assembly constants
 *   in asm-offsets.c must be updated accordingly
 * - thread_info is included in task_struct at an offset of 0.  This means that
 *   tp points to both thread_info and task_struct.
 */
struct thread_info {
    unsigned long   flags;      /* low level flags */
    int             preempt_count;  /* 0=>preemptible, <0=>BUG */
    mm_segment_t    addr_limit;
    /*
     * These stack pointers are overwritten on every system call or
     * exception.  SP is also saved to the stack it can be recovered when
     * overwritten.
     */
    long            kernel_sp;  /* Kernel stack pointer */
    long            user_sp;    /* User stack pointer */
    int             cpu;
};

/*
 * macros/functions for gaining access to the thread information structure
 *
 * preempt_count needs to be 1 initially, until the scheduler is functional.
 */
#define INIT_THREAD_INFO(tsk)   \
{                               \
    .flags      = 0,            \
    .preempt_count  = INIT_PREEMPT_COUNT,   \
    .addr_limit = KERNEL_DS,    \
}

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_RISCV_THREAD_INFO_H */

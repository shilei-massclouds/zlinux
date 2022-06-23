/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#include <linux/init.h>
#include <linux/linkage.h>

#include <asm/asm.h>
#include <asm/csr.h>
//#include <asm/unistd.h>
#include <asm/thread_info.h>
#include <asm/asm-offsets.h>
//#include <asm/errata_list.h>

.set resume_kernel, restore_all

ENTRY(handle_exception)
    ebreak

ret_from_exception:
    REG_L s0, PT_STATUS(sp)
    csrc CSR_STATUS, SR_IE
    andi s0, s0, SR_SPP
    bnez s0, resume_kernel

resume_userspace:
    /* Interrupts must be disabled here so flags are checked atomically */
    REG_L s0, TASK_TI_FLAGS(tp) /* current_thread_info->flags */
    andi s1, s0, _TIF_WORK_MASK
    bnez s1, work_pending

    /* Save unwound kernel stack pointer in thread_info */
    addi s0, sp, PT_SIZE_ON_STACK
    REG_S s0, TASK_TI_KERNEL_SP(tp)

    /*
     * Save TP into the scratch register , so we can find the kernel data
     * structures again.
     */
    csrw CSR_SCRATCH, tp

restore_all:
    REG_L a0, PT_STATUS(sp)
    /*
     * The current load reservation is effectively part of the processor's
     * state, in the sense that load reservations cannot be shared between
     * different hart contexts.  We can't actually save and restore a load
     * reservation, so instead here we clear any existing reservation --
     * it's always legal for implementations to clear load reservations at
     * any point (as long as the forward progress guarantee is kept, but
     * we'll ignore that here).
     *
     * Dangling load reservations can be the result of taking a trap in the
     * middle of an LR/SC sequence, but can also be the result of a taken
     * forward branch around an SC -- which is how we implement CAS.  As a
     * result we need to clear reservations between the last CAS and the
     * jump back to the new context.  While it is unlikely the store
     * completes, implementations are allowed to expand reservations to be
     * arbitrarily large.
     */
    REG_L  a2, PT_EPC(sp)
    REG_SC x0, a2, PT_EPC(sp)

    csrw CSR_STATUS, a0
    csrw CSR_EPC, a2

    REG_L x1,  PT_RA(sp)
    REG_L x3,  PT_GP(sp)
    REG_L x4,  PT_TP(sp)
    REG_L x5,  PT_T0(sp)
    REG_L x6,  PT_T1(sp)
    REG_L x7,  PT_T2(sp)
    REG_L x8,  PT_S0(sp)
    REG_L x9,  PT_S1(sp)
    REG_L x10, PT_A0(sp)
    REG_L x11, PT_A1(sp)
    REG_L x12, PT_A2(sp)
    REG_L x13, PT_A3(sp)
    REG_L x14, PT_A4(sp)
    REG_L x15, PT_A5(sp)
    REG_L x16, PT_A6(sp)
    REG_L x17, PT_A7(sp)
    REG_L x18, PT_S2(sp)
    REG_L x19, PT_S3(sp)
    REG_L x20, PT_S4(sp)
    REG_L x21, PT_S5(sp)
    REG_L x22, PT_S6(sp)
    REG_L x23, PT_S7(sp)
    REG_L x24, PT_S8(sp)
    REG_L x25, PT_S9(sp)
    REG_L x26, PT_S10(sp)
    REG_L x27, PT_S11(sp)
    REG_L x28, PT_T3(sp)
    REG_L x29, PT_T4(sp)
    REG_L x30, PT_T5(sp)
    REG_L x31, PT_T6(sp)

    REG_L x2,  PT_SP(sp)

    sret

work_pending:
    /* Enter slow path for supplementary processing */
    la ra, ret_from_exception
    andi s1, s0, _TIF_NEED_RESCHED
    bnez s1, work_resched
work_notifysig:
    /* Handle pending signals and notify-resume requests */
    csrs CSR_STATUS, SR_IE /* Enable interrupts for do_notify_resume() */
    move a0, sp /* pt_regs */
    move a1, s0 /* current_thread_info->flags */
    tail do_notify_resume
work_resched:
    tail schedule

END(handle_exception)

ENTRY(ret_from_kernel_thread)
    call schedule_tail
    /* Call fn(arg) */
    la ra, ret_from_exception
    move a0, s1
    jr s0
ENDPROC(ret_from_kernel_thread)

/*
 * Integer register context switch
 * The callee-saved registers must be saved and restored.
 *
 *   a0: previous task_struct (must be preserved across the switch)
 *   a1: next task_struct
 *
 * The value of a0 and a1 must be preserved by this function, as that's how
 * arguments are passed to schedule_tail.
 */
ENTRY(__switch_to)
    /* Save context into prev->thread */
    li    a4, TASK_THREAD_RA
    add   a3, a0, a4
    add   a4, a1, a4
    REG_S ra,  TASK_THREAD_RA_RA(a3)
    REG_S sp,  TASK_THREAD_SP_RA(a3)
    REG_S s0,  TASK_THREAD_S0_RA(a3)
    REG_S s1,  TASK_THREAD_S1_RA(a3)
    REG_S s2,  TASK_THREAD_S2_RA(a3)
    REG_S s3,  TASK_THREAD_S3_RA(a3)
    REG_S s4,  TASK_THREAD_S4_RA(a3)
    REG_S s5,  TASK_THREAD_S5_RA(a3)
    REG_S s6,  TASK_THREAD_S6_RA(a3)
    REG_S s7,  TASK_THREAD_S7_RA(a3)
    REG_S s8,  TASK_THREAD_S8_RA(a3)
    REG_S s9,  TASK_THREAD_S9_RA(a3)
    REG_S s10, TASK_THREAD_S10_RA(a3)
    REG_S s11, TASK_THREAD_S11_RA(a3)
    /* Restore context from next->thread */
    REG_L ra,  TASK_THREAD_RA_RA(a4)
    REG_L sp,  TASK_THREAD_SP_RA(a4)
    REG_L s0,  TASK_THREAD_S0_RA(a4)
    REG_L s1,  TASK_THREAD_S1_RA(a4)
    REG_L s2,  TASK_THREAD_S2_RA(a4)
    REG_L s3,  TASK_THREAD_S3_RA(a4)
    REG_L s4,  TASK_THREAD_S4_RA(a4)
    REG_L s5,  TASK_THREAD_S5_RA(a4)
    REG_L s6,  TASK_THREAD_S6_RA(a4)
    REG_L s7,  TASK_THREAD_S7_RA(a4)
    REG_L s8,  TASK_THREAD_S8_RA(a4)
    REG_L s9,  TASK_THREAD_S9_RA(a4)
    REG_L s10, TASK_THREAD_S10_RA(a4)
    REG_L s11, TASK_THREAD_S11_RA(a4)
    /* The offset of thread_info in task_struct is zero. */
    move tp, a1
    ret
ENDPROC(__switch_to)

/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_PTRACE_H
#define _ASM_RISCV_PTRACE_H

#include <uapi/asm/ptrace.h>
#include <asm/csr.h>
#include <linux/compiler.h>

#ifndef __ASSEMBLY__

struct pt_regs {
    unsigned long epc;
    unsigned long ra;
    unsigned long sp;
    unsigned long gp;
    unsigned long tp;
    unsigned long t0;
    unsigned long t1;
    unsigned long t2;
    unsigned long s0;
    unsigned long s1;
    unsigned long a0;
    unsigned long a1;
    unsigned long a2;
    unsigned long a3;
    unsigned long a4;
    unsigned long a5;
    unsigned long a6;
    unsigned long a7;
    unsigned long s2;
    unsigned long s3;
    unsigned long s4;
    unsigned long s5;
    unsigned long s6;
    unsigned long s7;
    unsigned long s8;
    unsigned long s9;
    unsigned long s10;
    unsigned long s11;
    unsigned long t3;
    unsigned long t4;
    unsigned long t5;
    unsigned long t6;
    /* Supervisor/Machine CSRs */
    unsigned long status;
    unsigned long badaddr;
    unsigned long cause;
    /* a0 value before the syscall */
    unsigned long orig_a0;
};

#define REG_FMT "%016lx"

#define user_mode(regs) (((regs)->status & SR_PP) == 0)

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_RISCV_PTRACE_H */

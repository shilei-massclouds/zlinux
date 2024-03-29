/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_SMP_H
#define _ASM_RISCV_SMP_H

#include <linux/cpumask.h>
#include <linux/irqreturn.h>
#include <linux/thread_info.h>

#define INVALID_HARTID ULONG_MAX

extern unsigned long boot_cpu_hartid;

struct riscv_ipi_ops {
    void (*ipi_inject)(const struct cpumask *target);
    void (*ipi_clear)(void);
};

/*
 * Mapping between linux logical cpu index and hartid.
 */
extern unsigned long __cpuid_to_hartid_map[NR_CPUS];
#define cpuid_to_hartid_map(cpu)    __cpuid_to_hartid_map[cpu]

/*
 * Obtains the hart ID of the currently executing task.  This relies on
 * THREAD_INFO_IN_TASK, but we define that unconditionally.
 */
#define raw_smp_processor_id() (current_thread_info()->cpu)

void __init setup_smp(void);

int riscv_hartid_to_cpuid(int hartid);

void handle_IPI(struct pt_regs *regs);

#endif /* _ASM_RISCV_SMP_H */

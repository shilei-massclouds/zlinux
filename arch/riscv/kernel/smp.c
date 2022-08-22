// SPDX-License-Identifier: GPL-2.0-only
/*
 * SMP initialisation and IPI support
 * Based on arch/arm64/kernel/smp.c
 *
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2015 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#include <linux/cpu.h>
/*
#include <linux/clockchips.h>
#include <linux/interrupt.h>
*/
#include <linux/module.h>
//#include <linux/profile.h>
#include <linux/smp.h>
#include <linux/sched.h>
/*
#include <linux/seq_file.h>
#include <linux/delay.h>
#include <linux/irq_work.h>
*/

#include <asm/sbi.h>
#include <asm/tlbflush.h>
//#include <asm/cacheflush.h>

enum ipi_message_type {
    IPI_RESCHEDULE,
    IPI_CALL_FUNC,
    IPI_CPU_STOP,
    IPI_IRQ_WORK,
    IPI_TIMER,
    IPI_MAX
};

unsigned long __cpuid_to_hartid_map[NR_CPUS] __ro_after_init = {
    [0 ... NR_CPUS-1] = INVALID_HARTID
};

void __init smp_setup_processor_id(void)
{
    cpuid_to_hartid_map(0) = boot_cpu_hartid;
}

/* A collection of single bit ipi messages.  */
static struct {
    unsigned long stats[IPI_MAX] ____cacheline_aligned;
    unsigned long bits ____cacheline_aligned;
} ipi_data[NR_CPUS] __cacheline_aligned;

static const struct riscv_ipi_ops *ipi_ops __ro_after_init;

int riscv_hartid_to_cpuid(int hartid)
{
    int i;

    for (i = 0; i < NR_CPUS; i++)
        if (cpuid_to_hartid_map(i) == hartid)
            return i;

    pr_err("Couldn't find cpu id for hartid [%d]\n", hartid);
    return -ENOENT;
}

void handle_IPI(struct pt_regs *regs)
{
    panic("%s: NO implementation!\n", __func__);
}

static void send_ipi_mask(const struct cpumask *mask, enum ipi_message_type op)
{
    int cpu;

    smp_mb__before_atomic();
    for_each_cpu(cpu, mask)
        set_bit(op, &ipi_data[cpu].bits);
    smp_mb__after_atomic();

    if (ipi_ops && ipi_ops->ipi_inject)
        ipi_ops->ipi_inject(mask);
    else
        pr_warn("SMP: IPI inject method not available\n");
}

void tick_broadcast(const struct cpumask *mask)
{
    send_ipi_mask(mask, IPI_TIMER);
}

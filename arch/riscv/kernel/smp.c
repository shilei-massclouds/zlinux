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

unsigned long __cpuid_to_hartid_map[NR_CPUS] __ro_after_init = {
    [0 ... NR_CPUS-1] = INVALID_HARTID
};

void __init smp_setup_processor_id(void)
{
    cpuid_to_hartid_map(0) = boot_cpu_hartid;
}

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

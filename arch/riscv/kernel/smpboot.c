// SPDX-License-Identifier: GPL-2.0-only
/*
 * SMP initialisation and IPI support
 * Based on arch/arm64/kernel/smp.c
 *
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2015 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#if 0
#include <linux/arch_topology.h>
#include <linux/module.h>
#endif
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched.h>
#if 0
#include <linux/kernel_stat.h>
#include <linux/notifier.h>
#endif
#include <linux/cpu.h>
#include <linux/percpu.h>
//#include <linux/delay.h>
#include <linux/err.h>
//#include <linux/irq.h>
#include <linux/of.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/mm.h>
#include <asm/cpu_ops.h>
#if 0
#include <asm/irq.h>
#include <asm/mmu_context.h>
#include <asm/numa.h>
#endif
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/sbi.h>
#include <asm/smp.h>
//#include <asm/alternative.h>

#include "head.h"

/*
 * C entry point for a secondary processor.
 */
asmlinkage __visible void smp_callin(void)
{
    panic("%s: Not implement!\n", __func__);
}

void __init setup_smp(void)
{
    struct device_node *dn;

    cpu_set_ops(0);

    for_each_of_cpu_node(dn) {
#if 0
        hart = riscv_of_processor_hartid(dn);
        if (hart < 0)
            continue;

        if (hart == cpuid_to_hartid_map(0)) {
            BUG_ON(found_boot_cpu);
            found_boot_cpu = 1;
            early_map_cpu_to_node(0, of_node_to_nid(dn));
            continue;
        }
        if (cpuid >= NR_CPUS) {
            pr_warn("Invalid cpuid [%d] for hartid [%d]\n",
                cpuid, hart);
            continue;
        }

        cpuid_to_hartid_map(cpuid) = hart;
        early_map_cpu_to_node(cpuid, of_node_to_nid(dn));
        cpuid++;
#endif
    }

    panic("%s: Not implement!\n", __func__);
}

// SPDX-License-Identifier: GPL-2.0-only
/*
 * HSM extension and cpu_ops implementation.
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 */

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sched/task_stack.h>
#include <asm/cpu_ops.h>
#include <asm/cpu_ops_sbi.h>
#include <asm/sbi.h>
#include <asm/smp.h>

extern char secondary_start_sbi[];
const struct cpu_operations cpu_ops_sbi;

/*
 * Ordered booting via HSM brings one cpu at a time. However, cpu hotplug can
 * be invoked from multiple threads in parallel. Define a per cpu data
 * to handle that.
 */
static DEFINE_PER_CPU(struct sbi_hart_boot_data, boot_data);

static int sbi_hsm_hart_start(unsigned long hartid, unsigned long saddr,
                              unsigned long priv)
{
    struct sbiret ret;

    ret = sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_START,
                    hartid, saddr, priv, 0, 0, 0);
    if (ret.error)
        return sbi_err_map_linux_errno(ret.error);
    else
        return 0;
}

static int sbi_cpu_prepare(unsigned int cpuid)
{
    if (!cpu_ops_sbi.cpu_start) {
        pr_err("cpu start method not defined for CPU [%d]\n", cpuid);
        return -ENODEV;
    }
    return 0;
}

static int sbi_cpu_start(unsigned int cpuid, struct task_struct *tidle)
{
    unsigned long hsm_data;
    int hartid = cpuid_to_hartid_map(cpuid);
    unsigned long boot_addr = __pa_symbol(secondary_start_sbi);
    struct sbi_hart_boot_data *bdata = &per_cpu(boot_data, cpuid);

    /* Make sure tidle is updated */
    smp_mb();
    bdata->task_ptr = tidle;
    bdata->stack_ptr = task_stack_page(tidle) + THREAD_SIZE;
    /* Make sure boot data is updated */
    smp_mb();
    hsm_data = __pa(bdata);
    return sbi_hsm_hart_start(hartid, boot_addr, hsm_data);
}

const struct cpu_operations cpu_ops_sbi = {
    .name           = "sbi",
    .cpu_prepare    = sbi_cpu_prepare,
    .cpu_start      = sbi_cpu_start,
};

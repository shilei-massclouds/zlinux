// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/sched.h>
#include <linux/console.h>
//#include <linux/screen_info.h>
#include <linux/of_fdt.h>
//#include <linux/of_platform.h>
#include <linux/sched/task.h>
//#include <linux/swiotlb.h>
#include <linux/smp.h>

//#include <asm/cpu_ops.h>
#include <asm/pgtable.h>
#include <asm/setup.h>
#include <asm/sections.h>
#include <asm/sbi.h>
#include <asm/tlbflush.h>
#include <asm/thread_info.h>

#include "head.h"

/*
 * The lucky hart to first increment this variable
 * will boot the other cores.
 * This is used before the kernel initializes the BSS
 * so it can't be in the BSS.
 */
atomic_t hart_lottery __section(.sdata);
unsigned long boot_cpu_hartid;

void __init parse_dtb(void)
{
    if (early_init_dt_scan(dtb_early_va))
        return;

    pr_err("No DTB passed to the kernel\n");
}

void __init setup_arch(char **cmdline_p)
{
    parse_dtb();

    parse_early_param();

    paging_init();

    {
        printk("%s: (%d)\n", __func__, NODE_DATA(0)->nr_zones);
    }

    if (early_init_dt_verify(__va(dtb_early_pa)))
        unflatten_device_tree();
    else
        pr_err("No DTB found in kernel mappings\n");

    misc_mem_init();
}

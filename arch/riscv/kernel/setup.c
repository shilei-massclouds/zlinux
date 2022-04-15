// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/of_fdt.h>

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

    //pr_err("No DTB passed to the kernel\n");
}

void __init setup_arch(char **cmdline_p)
{
    parse_early_param();
}

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
    /* Early scan of device tree from init memory */
    if (early_init_dt_scan(dtb_early_va)) {
        const char *name = of_flat_dt_get_machine_name();

        if (name) {
            pr_info("Machine model: %s\n", name);
        }
        return;
    }

    pr_err("No DTB passed to the kernel\n");
}

void __init setup_arch(char **cmdline_p)
{
    parse_dtb();
    setup_initial_init_mm(_stext, _etext, _edata, _end);

    *cmdline_p = boot_command_line;

#if 0
    early_ioremap_setup();
    jump_label_init();
#endif
    parse_early_param();

#if 0
    efi_init();
#endif
    paging_init();
    printk("l4(%d) l5(%d)\n", pgtable_l4_enabled, pgtable_l5_enabled);
    printk("%s: ================== PILOT ==================\n", __func__);

#if 0
    if (early_init_dt_verify(__va(XIP_FIXUP(dtb_early_pa))))
        unflatten_device_tree();
    else
        pr_err("No DTB found in kernel mappings\n");

    misc_mem_init();

    init_resources();
    sbi_init();

    setup_smp();

    riscv_fill_hwcap();
#endif
}

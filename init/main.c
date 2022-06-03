// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/main.c
 */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/cpu.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include <asm/setup.h>
#include "z_tests.h"

/*
 * Debug helper: via this flag we know that we are in 'early bootup code'
 * where only the boot processor is running with IRQ disabled.  This means
 * two things - IRQ must not be enabled before the flag is cleared and some
 * operations which are not allowed with IRQ disabled are allowed while the
 * flag is set.
 */
bool early_boot_irqs_disabled __read_mostly;

extern const struct obs_kernel_param __setup_start[], __setup_end[];

enum system_states system_state __read_mostly;
EXPORT_SYMBOL(system_state);

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];

static int __ref kernel_init(void *unused)
{
    z_tests();

    panic("%s: END!\n", __func__);
}

noinline void __ref rest_init(void)
{
    int pid;

    /*
     * We need to spawn init first so that it obtains pid 1, however
     * the init task will end up wanting to create kthreads, which, if
     * we schedule it before we create kthreadd, will OOPS.
     */
    pid = kernel_thread(kernel_init, NULL, CLONE_FS);

    panic("%s: pid(%d) END!\n", __func__, pid);
}

void __init __weak arch_call_rest_init(void)
{
    rest_init();
}

/*
 * Set up kernel memory allocators
 */
static void __init mm_init(void)
{
    mem_init();
    kmem_cache_init();
}

asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
{
    char *command_line;

    set_task_stack_end_magic(&init_task);
    smp_setup_processor_id();

    local_irq_disable();
    early_boot_irqs_disabled = true;

    /*
     * Interrupts are still disabled. Do necessary setups, then
     * enable them.
     */
    boot_cpu_init();

    pr_notice("%s", linux_banner);
    setup_arch(&command_line);

    setup_per_cpu_areas();

    build_all_zonelists(NULL);

    mm_init();

    setup_per_cpu_pageset();

    early_boot_irqs_disabled = false;
    local_irq_enable();

    /* TEST: kmalloc */
    {
        struct page *p;
        printk("%s: kmalloc ...\n", __func__);
        p = kmalloc(64, GFP_KERNEL);
        printk("%s: kfree (%pa)...\n", __func__, &p);
        kfree(p);
        panic("%s: alloc/free page\n", __func__);
    }

    /* Do the rest non-__init'ed, we're now alive */
    arch_call_rest_init();

    panic("%s: NOT implemented!", __func__);
}

/* Check for early params. */
static int __init
do_early_param(char *param, char *val, const char *unused, void *arg)
{
    const struct obs_kernel_param *p;

    for (p = __setup_start; p < __setup_end; p++) {
        if ((p->early && parameq(param, p->str)) ||
            (strcmp(param, "console") == 0 &&
             strcmp(p->str, "earlycon") == 0)
        ) {
            if (p->setup_func(val) != 0)
                pr_warn("Malformed early option '%s'\n", param);
        }
    }
    /* We accept everything at this stage. */
    return 0;
}

void __init parse_early_options(char *cmdline)
{
    parse_args("early options", cmdline, NULL, 0, 0, 0, NULL,
               do_early_param);
}

/* Arch code calls this early on, or if not, just before other parsing. */
void __init parse_early_param(void)
{
    static int done __initdata;
    static char tmp_cmdline[COMMAND_LINE_SIZE] __initdata;

    if (done)
        return;

    /* All fall through to do_early_param. */
    strlcpy(tmp_cmdline, boot_command_line, COMMAND_LINE_SIZE);
    parse_early_options(tmp_cmdline);
    done = 1;
}

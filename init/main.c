// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/main.c
 */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/linkage.h>

#include <asm/setup.h>

/* Untouched command line saved by arch-specific code. */
char __initdata boot_command_line[COMMAND_LINE_SIZE];

asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
{
    panic("%s: NOT implemented!", __func__);
}

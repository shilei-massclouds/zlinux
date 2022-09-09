// SPDX-License-Identifier: GPL-2.0
/*
 * Provide common bits of early_ioremap() support for architectures needing
 * temporary mappings during boot before ioremap() is available.
 *
 * This is mostly a direct copy of the x86 early_ioremap implementation.
 *
 * (C) Copyright 1995 1996, 2014 Linus Torvalds
 *
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <asm/fixmap.h>
#include <asm/early_ioremap.h>
#include "internal.h"

static void __iomem *prev_map[FIX_BTMAPS_SLOTS] __initdata;
static unsigned long prev_size[FIX_BTMAPS_SLOTS] __initdata;
static unsigned long slot_virt[FIX_BTMAPS_SLOTS] __initdata;

void __init early_ioremap_setup(void)
{
    int i;

    for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
        if (WARN_ON(prev_map[i]))
            break;

    for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
        slot_virt[i] = __fix_to_virt(FIX_BTMAP_BEGIN - NR_FIX_BTMAPS*i);
}

static int __init check_early_ioremap_leak(void)
{
    int count = 0;
    int i;

    for (i = 0; i < FIX_BTMAPS_SLOTS; i++)
        if (prev_map[i])
            count++;

    if (WARN(count, KERN_WARNING
             "Debug warning: early ioremap leak of %d areas detected.\n"
             "please boot with early_ioremap_debug and report "
             "the dmesg.\n",
             count))
        return 1;
    return 0;
}
late_initcall(check_early_ioremap_leak);

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 */
#include <linux/init.h>
#include <linux/libfdt.h>
#include <linux/pgtable.h>
//#include <asm/soc.h>

/*
 * This is called extremly early, before parse_dtb(), to allow initializing
 * SoC hardware before memory or any device driver initialization.
 */
void __init soc_early_init(void)
{
    printk("%s: ...\n", __func__);
}

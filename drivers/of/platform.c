// SPDX-License-Identifier: GPL-2.0+
/*
 *    Copyright (C) 2006 Benjamin Herrenschmidt, IBM Corp.
 *           <benh@kernel.crashing.org>
 *    and        Arnd Bergmann, IBM Corp.
 *    Merged from powerpc/kernel/of_platform.c and
 *    sparc{,64}/kernel/of_device.c by Stephen Rothwell
 */

#define pr_fmt(fmt) "OF: " fmt

#include <linux/errno.h>
#include <linux/module.h>
#if 0
#include <linux/amba/bus.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#endif
#include <linux/slab.h>
#if 0
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#endif

static int __init of_platform_default_populate_init(void)
{
    panic("%s: END!\n", __func__);
    return 0;
}
arch_initcall_sync(of_platform_default_populate_init);

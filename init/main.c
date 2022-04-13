// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/main.c
 */

#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/linkage.h>

asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
{
    panic("%s: NOT implemented!", __func__);
}

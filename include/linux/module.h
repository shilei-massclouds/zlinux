/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Dynamic loading of modules into the kernel.
 *
 * Rewritten by Richard Henderson <rth@tamu.edu> Dec 1996
 * Rewritten again by Rusty Russell, 2002
 */

#ifndef _LINUX_MODULE_H
#define _LINUX_MODULE_H

#include <linux/compiler.h>
#include <linux/cache.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/export.h>

#include <linux/percpu.h>
#if 0
#include <asm/module.h>
#endif

#define MODULE_NAME_LEN MAX_PARAM_PREFIX_LEN

#define __init_or_module
#define __initdata_or_module
#define __initconst_or_module
#define __INIT_OR_MODULE        .text
#define __INITDATA_OR_MODULE    .data
#define __INITRODATA_OR_MODULE  .section ".rodata","a",%progbits

struct module {
} ____cacheline_aligned __randomize_layout;

#endif /* _LINUX_MODULE_H */

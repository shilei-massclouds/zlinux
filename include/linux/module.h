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

#define __init_or_module

struct module {
} ____cacheline_aligned __randomize_layout;

#endif /* _LINUX_MODULE_H */

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

#ifndef MODULE
/**
 * module_init() - driver initialization entry point
 * @x: function to be run at kernel boot time or module insertion
 *
 * module_init() will either be called during do_initcalls() (if
 * builtin) or at module insertion time (if a module).  There can only
 * be one per module.
 */
#define module_init(x)  __initcall(x);

/**
 * module_exit() - driver exit entry point
 * @x: function to be run when driver is removed
 *
 * module_exit() will wrap the driver clean-up code
 * with cleanup_module() when used with rmmod when
 * the driver is a module.  If the driver is statically
 * compiled into the kernel, module_exit() has no effect.
 * There can only be one per module.
 */
#define module_exit(x)  __exitcall(x);
#else /* MODULE */
#error "NOT SUPPORT MODULE!"
#endif /* MODULE */

#ifdef MODULE
/* Creates an alias so file2alias.c can find device table. */
#define MODULE_DEVICE_TABLE(type, name) \
    extern typeof(name) __mod_##type##__##name##_device_table \
    __attribute__ ((unused, alias(__stringify(name))))
#else  /* !MODULE */
#define MODULE_DEVICE_TABLE(type, name)
#endif

/* This is the Right Way to get a module: if it fails, it's being removed,
 * so pretend it's not there. */
extern bool try_module_get(struct module *module);

#endif /* _LINUX_MODULE_H */

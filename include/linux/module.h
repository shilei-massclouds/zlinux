/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Dynamic loading of modules into the kernel.
 *
 * Rewritten by Richard Henderson <rth@tamu.edu> Dec 1996
 * Rewritten again by Rusty Russell, 2002
 */

#ifndef _LINUX_MODULE_H
#define _LINUX_MODULE_H

#include <linux/list.h>
#include <linux/stat.h>
#include <linux/buildid.h>
#include <linux/compiler.h>
#include <linux/cache.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/elf.h>
#include <linux/stringify.h>
#include <linux/kobject.h>
#include <linux/moduleparam.h>
#include <linux/jump_label.h>
#include <linux/export.h>
#include <linux/rbtree_latch.h>
#if 0
#include <linux/error-injection.h>
#include <linux/tracepoint-defs.h>
#include <linux/static_call_types.h>
#include <linux/cfi.h>
#endif
#include <linux/srcu.h>

#include <linux/percpu.h>
//#include <asm/module.h>

#define MODULE_NAME_LEN MAX_PARAM_PREFIX_LEN

#define __init_or_module
#define __initdata_or_module
#define __initconst_or_module
#define __INIT_OR_MODULE        .text
#define __INITDATA_OR_MODULE    .data
#define __INITRODATA_OR_MODULE  .section ".rodata","a",%progbits

enum module_state {
    MODULE_STATE_LIVE,  /* Normal state. */
    MODULE_STATE_COMING,    /* Full formed, running module_init. */
    MODULE_STATE_GOING, /* Going away. */
    MODULE_STATE_UNFORMED,  /* Still setting it up. */
};

struct module {
    enum module_state state;

    /* Member of list of modules */
    struct list_head list;

    /* Unique handle for this module */
    char name[MODULE_NAME_LEN];

    /* OTHERS */

    /* What modules depend on me? */
    struct list_head source_list;
    /* What modules do I depend on? */
    struct list_head target_list;

    /* Destruction function. */
    void (*exit)(void);

    struct jump_entry *jump_entries;
    unsigned int num_jump_entries;

    atomic_t refcnt;
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

/* Sometimes we know we already have a refcount, and it's easier not
   to handle the error case (which only happens with rmmod --wait). */
extern void __module_get(struct module *module);

/* This is the Right Way to get a module: if it fails, it's being removed,
 * so pretend it's not there. */
extern bool try_module_get(struct module *module);

extern void module_put(struct module *module);

/* FIXME: It'd be nice to isolate modules during init, too, so they
   aren't used before they (may) fail.  But presently too much code
   (IDE & SCSI) require entry into the module during init.*/
static inline bool module_is_live(struct module *mod)
{
    return mod->state != MODULE_STATE_GOING;
}

struct module *__module_address(unsigned long addr);

#endif /* _LINUX_MODULE_H */

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2002 Richard Henderson
 * Copyright (C) 2001 Rusty Russell, 2002, 2010 Rusty Russell IBM.
 */

#define INCLUDE_VERMAGIC

#include <linux/export.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/extable.h>
#include <linux/vmalloc.h>
#include <linux/elf.h>
#if 0
#include <linux/moduleloader.h>
#include <linux/module_signature.h>
#include <linux/kallsyms.h>
#include <linux/buildid.h>
#include <linux/file.h>
#include <linux/kernel_read_file.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/syscalls.h>
#include <linux/fcntl.h>
#include <linux/rcupdate.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/moduleparam.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/vermagic.h>
#include <linux/notifier.h>
#include <linux/sched.h>
#include <linux/device.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <linux/license.h>
#include <asm/sections.h>
#include <linux/tracepoint.h>
#include <linux/ftrace.h>
#include <linux/livepatch.h>
#include <linux/async.h>
#include <linux/percpu.h>
#include <linux/jump_label.h>
#include <linux/bsearch.h>
#include <linux/dynamic_debug.h>
#include <linux/audit.h>
#include <uapi/linux/module.h>
#include "module-internal.h"
#endif
#include <linux/pfn.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/set_memory.h>

static struct mod_tree_root {
    struct latch_tree_root root;
    unsigned long addr_min;
    unsigned long addr_max;
} mod_tree __cacheline_aligned = {
    .addr_min = -1UL,
};

#define module_addr_min mod_tree.addr_min
#define module_addr_max mod_tree.addr_max

void __module_get(struct module *module)
{
    if (module) {
        preempt_disable();
        atomic_inc(&module->refcnt);
        preempt_enable();
    }
}
EXPORT_SYMBOL(__module_get);

bool try_module_get(struct module *module)
{
    bool ret = true;

    if (module) {
        preempt_disable();
        /* Note: here, we can fail to get a reference */
        if (likely(module_is_live(module) &&
                   atomic_inc_not_zero(&module->refcnt) != 0))
            /* trace module */;
        else
            ret = false;

        preempt_enable();
    }
    return ret;
}
EXPORT_SYMBOL(try_module_get);

void module_put(struct module *module)
{
    int ret;

    if (module) {
        preempt_disable();
        ret = atomic_dec_if_positive(&module->refcnt);
        WARN_ON(ret < 0);   /* Failed to put refcount */
        preempt_enable();
    }
}
EXPORT_SYMBOL(module_put);

/**
 * __module_address() - get the module which contains an address.
 * @addr: the address.
 *
 * Must be called with preempt disabled or module mutex held so that
 * module doesn't get freed during this.
 */
struct module *__module_address(unsigned long addr)
{
    struct module *mod;

    if (addr < module_addr_min || addr > module_addr_max)
        return NULL;

    panic("%s: END!\n", __func__);
}

/* Given an address, look for it in the module exception tables. */
const struct exception_table_entry *search_module_extables(unsigned long addr)
{
    const struct exception_table_entry *e = NULL;
    struct module *mod;

    preempt_disable();
    mod = __module_address(addr);
    if (!mod)
        goto out;

    panic("%s: END!\n", __func__);

 out:
    preempt_enable();

    /*
     * Now, if we found one, we are running inside it now, hence
     * we cannot unload the module, hence no refcnt needed.
     */
    return e;
}

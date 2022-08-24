// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/proc/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/cache.h>
#include <linux/time.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/pid_namespace.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/completion.h>
//#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/file.h>
#include <linux/limits.h>
#include <linux/init.h>
#include <linux/module.h>
//#include <linux/sysctl.h>
//#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/bug.h>

#include <linux/uaccess.h>

#include "internal.h"

static struct kmem_cache *proc_inode_cachep __ro_after_init;
static struct kmem_cache *pde_opener_cache __ro_after_init;

static void init_once(void *foo)
{
    struct proc_inode *ei = (struct proc_inode *) foo;

    inode_init_once(&ei->vfs_inode);
}

void __init proc_init_kmemcache(void)
{
    proc_inode_cachep =
        kmem_cache_create("proc_inode_cache",
                          sizeof(struct proc_inode),
                          0, (SLAB_RECLAIM_ACCOUNT|
                              SLAB_MEM_SPREAD|SLAB_ACCOUNT|SLAB_PANIC),
                          init_once);

    pde_opener_cache =
        kmem_cache_create("pde_opener", sizeof(struct pde_opener), 0,
                          SLAB_ACCOUNT|SLAB_PANIC, NULL);
    proc_dir_entry_cache =
        kmem_cache_create_usercopy("proc_dir_entry", SIZEOF_PDE, 0, SLAB_PANIC,
                                   offsetof(struct proc_dir_entry, inline_name),
                                   SIZEOF_PDE_INLINE_NAME, NULL);
    BUILD_BUG_ON(sizeof(struct proc_dir_entry) >= SIZEOF_PDE);
}

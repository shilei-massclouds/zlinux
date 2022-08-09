// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/fs/file_table.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 1997 David S. Miller (davem@caip.rutgers.edu)
 */

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/file.h>
//#include <linux/fdtable.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
//#include <linux/security.h>
#include <linux/cred.h>
//#include <linux/eventpoll.h>
#include <linux/rcupdate.h>
#include <linux/mount.h>
#if 0
#include <linux/capability.h>
#include <linux/cdev.h>
#include <linux/fsnotify.h>
#include <linux/sysctl.h>
#endif
#include <linux/percpu_counter.h>
#include <linux/percpu.h>
#if 0
#include <linux/task_work.h>
#include <linux/ima.h>
#endif
#include <linux/swap.h>

#include <linux/atomic.h>

#include "internal.h"

void fput(struct file *file)
{
    fput_many(file, 1);
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(fput);

void fput_many(struct file *file, unsigned int refs)
{
    panic("%s: END!\n", __func__);
}

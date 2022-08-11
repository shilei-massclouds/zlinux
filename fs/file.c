// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/file.c
 *
 *  Copyright (C) 1998-1999, Stephen Tweedie and Bill Hawes
 *
 *  Manage the dynamic fd arrays in the process files_struct.
 */

//#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
//#include <linux/close_range.h>
//#include <net/sock.h>

#include "internal.h"

bool get_close_on_exec(unsigned int fd)
{
#if 0
    struct files_struct *files = current->files;
    struct fdtable *fdt;
    bool res;
    rcu_read_lock();
    fdt = files_fdtable(files);
    res = close_on_exec(fd, fdt);
    rcu_read_unlock();
    return res;
#endif
    panic("%s: END!\n", __func__);
}

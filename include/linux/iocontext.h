/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IOCONTEXT_H
#define IOCONTEXT_H

#include <linux/radix-tree.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>

/*
 * I/O subsystem state of the associated processes.  It is refcounted
 * and kmalloc'ed. These could be shared between processes.
 */
struct io_context {
    atomic_long_t   refcount;
    atomic_t        active_ref;

    unsigned short  ioprio;
};

#endif /* IOCONTEXT_H */

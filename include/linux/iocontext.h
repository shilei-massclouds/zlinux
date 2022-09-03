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

void put_io_context(struct io_context *ioc);
void exit_io_context(struct task_struct *task);
int __copy_io(unsigned long clone_flags, struct task_struct *tsk);
static inline int copy_io(unsigned long clone_flags,
                          struct task_struct *tsk)
{
    if (!current->io_context)
        return 0;
    return __copy_io(clone_flags, tsk);
}

#endif /* IOCONTEXT_H */

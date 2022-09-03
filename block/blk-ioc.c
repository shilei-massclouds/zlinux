// SPDX-License-Identifier: GPL-2.0
/*
 * Functions related to io context handling
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/security.h>
#include <linux/sched/task.h>

#include "blk.h"
#include "blk-mq-sched.h"

/*
 * For io context allocations
 */
static struct kmem_cache *iocontext_cachep;

static inline void ioc_exit_icqs(struct io_context *ioc)
{
}
static inline bool ioc_delay_free(struct io_context *ioc)
{
    return false;
}

/**
 * put_io_context - put a reference of io_context
 * @ioc: io_context to put
 *
 * Decrement reference count of @ioc and release it if the count reaches
 * zero.
 */
void put_io_context(struct io_context *ioc)
{
    BUG_ON(atomic_long_read(&ioc->refcount) <= 0);
    if (atomic_long_dec_and_test(&ioc->refcount) && !ioc_delay_free(ioc))
        kmem_cache_free(iocontext_cachep, ioc);
}
EXPORT_SYMBOL_GPL(put_io_context);

/* Called by the exiting task */
void exit_io_context(struct task_struct *task)
{
    struct io_context *ioc;

    task_lock(task);
    ioc = task->io_context;
    task->io_context = NULL;
    task_unlock(task);

    if (atomic_dec_and_test(&ioc->active_ref)) {
        ioc_exit_icqs(ioc);
        put_io_context(ioc);
    }
}

static struct io_context *alloc_io_context(gfp_t gfp_flags, int node)
{
    struct io_context *ioc;

    ioc = kmem_cache_alloc_node(iocontext_cachep,
                                gfp_flags | __GFP_ZERO,
                                node);
    if (unlikely(!ioc))
        return NULL;

    atomic_long_set(&ioc->refcount, 1);
    atomic_set(&ioc->active_ref, 1);
    return ioc;
}

int __copy_io(unsigned long clone_flags, struct task_struct *tsk)
{
    struct io_context *ioc = current->io_context;

    /*
     * Share io context with parent, if CLONE_IO is set
     */
    if (clone_flags & CLONE_IO) {
        atomic_inc(&ioc->active_ref);
        tsk->io_context = ioc;
    } else if (ioprio_valid(ioc->ioprio)) {
        tsk->io_context = alloc_io_context(GFP_KERNEL, NUMA_NO_NODE);
        if (!tsk->io_context)
            return -ENOMEM;
        tsk->io_context->ioprio = ioc->ioprio;
    }

    return 0;
}

static int __init blk_ioc_init(void)
{
    iocontext_cachep =
        kmem_cache_create("blkdev_ioc", sizeof(struct io_context), 0,
                          SLAB_PANIC, NULL);
    return 0;
}
subsys_initcall(blk_ioc_init);

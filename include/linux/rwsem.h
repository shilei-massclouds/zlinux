/* SPDX-License-Identifier: GPL-2.0 */
/* rwsem.h: R/W semaphores, public interface
 *
 * Written by David Howells (dhowells@redhat.com).
 * Derived from asm-i386/semaphore.h
 */

#ifndef _LINUX_RWSEM_H
#define _LINUX_RWSEM_H

#include <linux/linkage.h>

#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/err.h>

#define RWSEM_UNLOCKED_VALUE    0L

/*
 * For an uncontended rwsem, count and owner are the only fields a task
 * needs to touch when acquiring the rwsem. So they are put next to each
 * other to increase the chance that they will share the same cacheline.
 *
 * In a contended rwsem, the owner is likely the most frequently accessed
 * field in the structure as the optimistic waiter that holds the osq lock
 * will spin on owner. For an embedded rwsem, other hot fields in the
 * containing structure should be moved further away from the rwsem to
 * reduce the chance that they will share the same cacheline causing
 * cacheline bouncing problem.
 */
struct rw_semaphore {
    atomic_long_t count;
    /*
     * Write owner or one of the read owners as well flags regarding
     * the current state of the rwsem. Can be used as a speculative
     * check to see if the write owner is running on the cpu.
     */
    atomic_long_t owner;
#if 0
    struct optimistic_spin_queue osq; /* spinner MCS lock */
#endif
    raw_spinlock_t wait_lock;
    struct list_head wait_list;
};

extern void __init_rwsem(struct rw_semaphore *sem, const char *name,
                         struct lock_class_key *key);

#define init_rwsem(sem)                 \
do {                                    \
    static struct lock_class_key __key; \
                                        \
    __init_rwsem((sem), #sem, &__key);  \
} while (0)

#endif /* _LINUX_RWSEM_H */

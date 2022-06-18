/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Read-Copy Update mechanism for mutual exclusion
 */
#ifndef __LINUX_RCUPDATE_H
#define __LINUX_RCUPDATE_H

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/atomic.h>
#include <linux/irqflags.h>
#include <linux/preempt.h>
//#include <linux/bottom_half.h>
#include <asm/processor.h>
#include <linux/cpumask.h>

#define rcu_check_sparse(p, space)

#define __rcu_dereference_check(p, local, c, space) \
({ \
    /* Dependency order vs. p above. */ \
    typeof(*p) *local = (typeof(*p) *__force)READ_ONCE(p); \
    rcu_check_sparse(p, space); \
    ((typeof(*p) __force __kernel *)(local)); \
})

/**
 * rcu_dereference_check() - rcu_dereference with debug checking
 * @p: The pointer to read, prior to dereferencing
 * @c: The conditions under which the dereference will take place
 *
 * Do an rcu_dereference(), but check that the conditions under which the
 * dereference will take place are correct.  Typically the conditions
 * indicate the various locking conditions that should be held at that
 * point.  The check should return true if the conditions are satisfied.
 * An implicit check for being in an RCU read-side critical section
 * (rcu_read_lock()) is included.
 *
 * For example:
 *
 *  bar = rcu_dereference_check(foo->bar, lockdep_is_held(&foo->lock));
 *
 * could be used to indicate to lockdep that foo->bar may only be dereferenced
 * if either rcu_read_lock() is held, or that the lock required to replace
 * the bar struct at foo->bar is held.
 *
 * Note that the list of conditions may also include indications of when a lock
 * need not be held, for example during initialisation or destruction of the
 * target struct:
 *
 *  bar = rcu_dereference_check(foo->bar, lockdep_is_held(&foo->lock) ||
 *                        atomic_read(&foo->usage) == 0);
 *
 * Inserts memory barriers on architectures that require them
 * (currently only the Alpha), prevents the compiler from refetching
 * (and from merging fetches), and, more importantly, documents exactly
 * which pointers are protected by RCU and checks that the pointer is
 * annotated as __rcu.
 */
#define rcu_dereference_check(p, c) \
    __rcu_dereference_check((p), __UNIQUE_ID(rcu), \
                            (c) || rcu_read_lock_held(), __rcu)

/**
 * rcu_dereference() - fetch RCU-protected pointer for dereferencing
 * @p: The pointer to read, prior to dereferencing
 *
 * This is a simple wrapper around rcu_dereference_check().
 */
#define rcu_dereference(p) rcu_dereference_check(p, 0)

/* Exported common interfaces */
void call_rcu(struct rcu_head *head, rcu_callback_t func);

void synchronize_rcu(void);

static inline void __rcu_read_lock(void)
{
    preempt_disable();
}

static inline void __rcu_read_unlock(void)
{
    preempt_enable();
}

/**
 * rcu_read_lock() - mark the beginning of an RCU read-side critical section
 *
 * When synchronize_rcu() is invoked on one CPU while other CPUs
 * are within RCU read-side critical sections, then the
 * synchronize_rcu() is guaranteed to block until after all the other
 * CPUs exit their critical sections.  Similarly, if call_rcu() is invoked
 * on one CPU while other CPUs are within RCU read-side critical
 * sections, invocation of the corresponding RCU callback is deferred
 * until after the all the other CPUs exit their critical sections.
 *
 * In v5.0 and later kernels, synchronize_rcu() and call_rcu() also
 * wait for regions of code with preemption disabled, including regions of
 * code with interrupts or softirqs disabled.  In pre-v5.0 kernels, which
 * define synchronize_sched(), only code enclosed within rcu_read_lock()
 * and rcu_read_unlock() are guaranteed to be waited for.
 *
 * Note, however, that RCU callbacks are permitted to run concurrently
 * with new RCU read-side critical sections.  One way that this can happen
 * is via the following sequence of events: (1) CPU 0 enters an RCU
 * read-side critical section, (2) CPU 1 invokes call_rcu() to register
 * an RCU callback, (3) CPU 0 exits the RCU read-side critical section,
 * (4) CPU 2 enters a RCU read-side critical section, (5) the RCU
 * callback is invoked.  This is legal, because the RCU read-side critical
 * section that was running concurrently with the call_rcu() (and which
 * therefore might be referencing something that the corresponding RCU
 * callback would free up) has completed before the corresponding
 * RCU callback is invoked.
 *
 * RCU read-side critical sections may be nested.  Any deferred actions
 * will be deferred until the outermost RCU read-side critical section
 * completes.
 *
 * You can avoid reading and understanding the next paragraph by
 * following this rule: don't put anything in an rcu_read_lock() RCU
 * read-side critical section that would block in a !PREEMPTION kernel.
 * But if you want the full story, read on!
 *
 * In non-preemptible RCU implementations (pure TREE_RCU and TINY_RCU),
 * it is illegal to block while in an RCU read-side critical section.
 * In preemptible RCU implementations (PREEMPT_RCU) in CONFIG_PREEMPTION
 * kernel builds, RCU read-side critical sections may be preempted,
 * but explicit blocking is illegal.  Finally, in preemptible RCU
 * implementations in real-time (with -rt patchset) kernel builds, RCU
 * read-side critical sections may be preempted and they may also block, but
 * only when acquiring spinlocks that are subject to priority inheritance.
 */
static __always_inline void rcu_read_lock(void)
{
    __rcu_read_lock();
    __acquire(RCU);
}

/**
 * rcu_read_unlock() - marks the end of an RCU read-side critical section.
 *
 * In almost all situations, rcu_read_unlock() is immune from deadlock.
 * In recent kernels that have consolidated synchronize_sched() and
 * synchronize_rcu_bh() into synchronize_rcu(), this deadlock immunity
 * also extends to the scheduler's runqueue and priority-inheritance
 * spinlocks, courtesy of the quiescent-state deferral that is carried
 * out when rcu_read_unlock() is invoked with interrupts disabled.
 *
 * See rcu_read_lock() for more information.
 */
static inline void rcu_read_unlock(void)
{
    __release(RCU);
    __rcu_read_unlock();
}

#include <linux/rcutree.h>

#endif /* __LINUX_RCUPDATE_H */

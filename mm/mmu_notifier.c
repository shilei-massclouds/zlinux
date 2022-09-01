// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/mmu_notifier.c
 *
 *  Copyright (C) 2008  Qumranet, Inc.
 *  Copyright (C) 2008  SGI
 *             Christoph Lameter <cl@linux.com>
 */

#include <linux/rculist.h>
#include <linux/mmu_notifier.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/err.h>
//#include <linux/interval_tree.h>
#include <linux/srcu.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>

/*
 * The mmu_notifier_subscriptions structure is allocated and installed in
 * mm->notifier_subscriptions inside the mm_take_all_locks() protected
 * critical section and it's released only when mm_count reaches zero
 * in mmdrop().
 */
struct mmu_notifier_subscriptions {
    /* all mmu notifiers registered in this mm are queued in this list */
    struct hlist_head list;
    bool has_itree;
    /* to serialize the list modifications and hlist_unhashed */
    spinlock_t lock;
    unsigned long invalidate_seq;
    unsigned long active_invalidate_ranges;
    struct rb_root_cached itree;
    wait_queue_head_t wq;
    struct hlist_head deferred_list;
};

/* global SRCU for all MMs */
DEFINE_STATIC_SRCU(srcu);

/*
 * If no young bitflag is supported by the hardware, ->clear_flush_young can
 * unmap the address and return 1 or 0 depending if the mapping previously
 * existed or not.
 */
int __mmu_notifier_clear_flush_young(struct mm_struct *mm,
                    unsigned long start,
                    unsigned long end)
{
    struct mmu_notifier *subscription;
    int young = 0, id;

    id = srcu_read_lock(&srcu);
    hlist_for_each_entry_rcu(subscription,
                             &mm->notifier_subscriptions->list, hlist,
                             srcu_read_lock_held(&srcu)) {
        if (subscription->ops->clear_flush_young)
            young |=
                subscription->ops->clear_flush_young(subscription, mm,
                                                     start, end);
    }
    srcu_read_unlock(&srcu, id);

    return young;
}

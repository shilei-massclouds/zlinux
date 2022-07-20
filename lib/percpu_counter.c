// SPDX-License-Identifier: GPL-2.0
/*
 * Fast batching percpu counters.
 */

#include <linux/percpu_counter.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/module.h>
#if 0
#include <linux/debugobjects.h>
#endif

static LIST_HEAD(percpu_counters);
static DEFINE_SPINLOCK(percpu_counters_lock);

int __percpu_counter_init(struct percpu_counter *fbc, s64 amount, gfp_t gfp,
                          struct lock_class_key *key)
{
    unsigned long flags __maybe_unused;

    raw_spin_lock_init(&fbc->lock);
    fbc->count = amount;
    fbc->counters = alloc_percpu_gfp(s32, gfp);
    if (!fbc->counters)
        return -ENOMEM;

    INIT_LIST_HEAD(&fbc->list);
    spin_lock_irqsave(&percpu_counters_lock, flags);
    list_add(&fbc->list, &percpu_counters);
    spin_unlock_irqrestore(&percpu_counters_lock, flags);
    return 0;
}
EXPORT_SYMBOL(__percpu_counter_init);

void percpu_counter_destroy(struct percpu_counter *fbc)
{
    unsigned long flags __maybe_unused;

    if (!fbc->counters)
        return;

    spin_lock_irqsave(&percpu_counters_lock, flags);
    list_del(&fbc->list);
    spin_unlock_irqrestore(&percpu_counters_lock, flags);
    free_percpu(fbc->counters);
    fbc->counters = NULL;
}
EXPORT_SYMBOL(percpu_counter_destroy);

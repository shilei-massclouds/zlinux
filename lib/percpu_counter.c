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

int percpu_counter_batch __read_mostly = 32;
EXPORT_SYMBOL(percpu_counter_batch);

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

/*
 * This function is both preempt and irq safe. The former is due to explicit
 * preemption disable. The latter is guaranteed by the fact that the slow path
 * is explicitly protected by an irq-safe spinlock whereas the fast patch uses
 * this_cpu_add which is irq-safe by definition. Hence there is no need muck
 * with irq state before calling this one
 */
void percpu_counter_add_batch(struct percpu_counter *fbc, s64 amount, s32 batch)
{
    s64 count;

    preempt_disable();
    count = __this_cpu_read(*fbc->counters) + amount;
    if (abs(count) >= batch) {
        unsigned long flags;
        raw_spin_lock_irqsave(&fbc->lock, flags);
        fbc->count += count;
        __this_cpu_sub(*fbc->counters, count - amount);
        raw_spin_unlock_irqrestore(&fbc->lock, flags);
    } else {
        this_cpu_add(*fbc->counters, amount);
    }
    preempt_enable();
}
EXPORT_SYMBOL(percpu_counter_add_batch);

/*
 * Add up all the per-cpu counts, return the result.  This is a more accurate
 * but much slower version of percpu_counter_read_positive()
 */
s64 __percpu_counter_sum(struct percpu_counter *fbc)
{
    s64 ret;
    int cpu;
    unsigned long flags;

    raw_spin_lock_irqsave(&fbc->lock, flags);
    ret = fbc->count;
    for_each_online_cpu(cpu) {
        s32 *pcount = per_cpu_ptr(fbc->counters, cpu);
        ret += *pcount;
    }
    raw_spin_unlock_irqrestore(&fbc->lock, flags);
    return ret;
}
EXPORT_SYMBOL(__percpu_counter_sum);

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PERCPU_COUNTER_H
#define _LINUX_PERCPU_COUNTER_H
/*
 * A simple "approximate counter" for use in ext2 and ext3 superblocks.
 *
 * WARNING: these things are HUGE.  4 kbytes per counter on 32-way P4.
 */

#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/list.h>
#include <linux/threads.h>
#include <linux/percpu.h>
#include <linux/types.h>
#include <linux/gfp.h>

struct percpu_counter {
    raw_spinlock_t lock;
    s64 count;
    struct list_head list;  /* All percpu_counters are on a list */
    s32 __percpu *counters;
};

int __percpu_counter_init(struct percpu_counter *fbc, s64 amount, gfp_t gfp,
              struct lock_class_key *key);

#define percpu_counter_init(fbc, value, gfp)                \
    ({                              \
        static struct lock_class_key __key;         \
                                    \
        __percpu_counter_init(fbc, value, gfp, &__key);     \
    })

void percpu_counter_destroy(struct percpu_counter *fbc);
void percpu_counter_set(struct percpu_counter *fbc, s64 amount);
void percpu_counter_add_batch(struct percpu_counter *fbc,
                              s64 amount, s32 batch);

#endif /* _LINUX_PERCPU_COUNTER_H */

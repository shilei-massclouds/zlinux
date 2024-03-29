/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BLOCKGROUP_LOCK_H
#define _LINUX_BLOCKGROUP_LOCK_H
/*
 * Per-blockgroup locking for ext2 and ext3.
 *
 * Simple hashed spinlocking.
 */

#include <linux/spinlock.h>
#include <linux/cache.h>

#define NR_BG_LOCKS (4 << ilog2(NR_CPUS < 32 ? NR_CPUS : 32))

struct bgl_lock {
    spinlock_t lock;
} ____cacheline_aligned_in_smp;

struct blockgroup_lock {
    struct bgl_lock locks[NR_BG_LOCKS];
};

static inline void bgl_lock_init(struct blockgroup_lock *bgl)
{
    int i;

    for (i = 0; i < NR_BG_LOCKS; i++)
        spin_lock_init(&bgl->locks[i].lock);
}

#endif /* _LINUX_BLOCKGROUP_LOCK_H */

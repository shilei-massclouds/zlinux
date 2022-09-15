// SPDX-License-Identifier: GPL-2.0-only

#include <linux/stat.h>
#include <linux/sysctl.h>
#include <linux/slab.h>
#include <linux/cred.h>
#include <linux/hash.h>
#include <linux/user_namespace.h>

struct ucounts init_ucounts = {
    .ns    = &init_user_ns,
    .uid   = GLOBAL_ROOT_UID,
    .count = ATOMIC_INIT(1),
};

static DEFINE_SPINLOCK(ucounts_lock);

static inline bool get_ucounts_or_wrap(struct ucounts *ucounts)
{
    /* Returns true on a successful get, false if the count wraps. */
    return !atomic_add_negative(1, &ucounts->count);
}

void put_ucounts(struct ucounts *ucounts)
{
    unsigned long flags;

    if (atomic_dec_and_lock_irqsave(&ucounts->count, &ucounts_lock,
                                    flags)) {
        hlist_del_init(&ucounts->node);
        spin_unlock_irqrestore(&ucounts_lock, flags);
        put_user_ns(ucounts->ns);
        kfree(ucounts);
    }
}

struct ucounts *get_ucounts(struct ucounts *ucounts)
{
    if (!get_ucounts_or_wrap(ucounts)) {
        put_ucounts(ucounts);
        ucounts = NULL;
    }
    return ucounts;
}

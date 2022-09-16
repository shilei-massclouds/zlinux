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

static void do_dec_rlimit_put_ucounts(struct ucounts *ucounts,
                                      struct ucounts *last,
                                      enum ucount_type type)
{
    struct ucounts *iter, *next;
    for (iter = ucounts; iter != last; iter = next) {
        long dec = atomic_long_sub_return(1, &iter->ucount[type]);
        WARN_ON_ONCE(dec < 0);
        next = iter->ns->ucounts;
        if (dec == 0)
            put_ucounts(iter);
    }
}

long inc_rlimit_get_ucounts(struct ucounts *ucounts,
                            enum ucount_type type)
{
    /* Caller must hold a reference to ucounts */
    struct ucounts *iter;
    long max = LONG_MAX;
    long dec, ret = 0;

    for (iter = ucounts; iter; iter = iter->ns->ucounts) {
        long new = atomic_long_add_return(1, &iter->ucount[type]);
        if (new < 0 || new > max)
            goto unwind;
        if (iter == ucounts)
            ret = new;
        max = READ_ONCE(iter->ns->ucount_max[type]);
        /*
         * Grab an extra ucount reference for the caller when
         * the rlimit count was previously 0.
         */
        if (new != 1)
            continue;
        if (!get_ucounts(iter))
            goto dec_unwind;
    }
    return ret;
dec_unwind:
    dec = atomic_long_sub_return(1, &iter->ucount[type]);
    WARN_ON_ONCE(dec < 0);
unwind:
    do_dec_rlimit_put_ucounts(ucounts, iter, type);
    return 0;
}

void dec_rlimit_put_ucounts(struct ucounts *ucounts,
                            enum ucount_type type)
{
    do_dec_rlimit_put_ucounts(ucounts, NULL, type);
}

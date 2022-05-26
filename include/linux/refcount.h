/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_REFCOUNT_H
#define _LINUX_REFCOUNT_H

#include <linux/atomic.h>

enum refcount_saturation_type {
    REFCOUNT_ADD_NOT_ZERO_OVF,
    REFCOUNT_ADD_OVF,
    REFCOUNT_ADD_UAF,
    REFCOUNT_SUB_UAF,
    REFCOUNT_DEC_LEAK,
};

/**
 * struct refcount_t - variant of atomic_t specialized for reference counts
 * @refs: atomic_t counter field
 *
 * The counter saturates at REFCOUNT_SATURATED and will not move once
 * there. This avoids wrapping the counter and causing 'spurious'
 * use-after-free bugs.
 */
typedef struct refcount_struct {
    atomic_t refs;
} refcount_t;

void refcount_warn_saturate(refcount_t *r, enum refcount_saturation_type t);

#define REFCOUNT_INIT(n)    { .refs = ATOMIC_INIT(n), }
#define REFCOUNT_MAX        INT_MAX
#define REFCOUNT_SATURATED  (INT_MIN / 2)

/**
 * refcount_set - set a refcount's value
 * @r: the refcount
 * @n: value to which the refcount will be set
 */
static inline void refcount_set(refcount_t *r, int n)
{
    atomic_set(&r->refs, n);
}

static inline void __refcount_add(int i, refcount_t *r, int *oldp)
{
    int old = atomic_fetch_add_relaxed(i, &r->refs);

    if (oldp)
        *oldp = old;

    if (unlikely(!old))
        refcount_warn_saturate(r, REFCOUNT_ADD_UAF);
    else if (unlikely(old < 0 || old + i < 0))
        refcount_warn_saturate(r, REFCOUNT_ADD_OVF);
}

static inline void __refcount_inc(refcount_t *r, int *oldp)
{
    __refcount_add(1, r, oldp);
}

/**
 * refcount_inc - increment a refcount
 * @r: the refcount to increment
 *
 * Similar to atomic_inc(), but will saturate at REFCOUNT_SATURATED and WARN.
 *
 * Provides no memory ordering, it is assumed the caller already has a
 * reference on the object.
 *
 * Will WARN if the refcount is 0, as this represents a possible use-after-free
 * condition.
 */
static inline void refcount_inc(refcount_t *r)
{
    __refcount_inc(r, NULL);
}

static inline __must_check bool
__refcount_sub_and_test(int i, refcount_t *r, int *oldp)
{
    int old = atomic_fetch_sub_release(i, &r->refs);

    if (oldp)
        *oldp = old;

    if (old == i) {
        smp_acquire__after_ctrl_dep();
        return true;
    }

    if (unlikely(old < 0 || old - i < 0))
        refcount_warn_saturate(r, REFCOUNT_SUB_UAF);

    return false;
}

static inline __must_check bool
__refcount_dec_and_test(refcount_t *r, int *oldp)
{
    return __refcount_sub_and_test(1, r, oldp);
}

/**
 * refcount_dec_and_test - decrement a refcount and test if it is 0
 * @r: the refcount
 *
 * Similar to atomic_dec_and_test(), it will WARN on underflow and fail to
 * decrement when saturated at REFCOUNT_SATURATED.
 *
 * Provides release memory ordering, such that prior loads and stores are done
 * before, and provides an acquire ordering on success such that free()
 * must come after.
 *
 * Return: true if the resulting refcount is 0, false otherwise
 */
static inline __must_check bool refcount_dec_and_test(refcount_t *r)
{
    return __refcount_dec_and_test(r, NULL);
}

#endif /* _LINUX_REFCOUNT_H */

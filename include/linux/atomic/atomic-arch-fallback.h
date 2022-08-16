// SPDX-License-Identifier: GPL-2.0

// Generated by scripts/atomic/gen-atomic-fallback.sh
// DO NOT MODIFY THIS FILE DIRECTLY

#ifndef _LINUX_ATOMIC_FALLBACK_H
#define _LINUX_ATOMIC_FALLBACK_H

#include <linux/compiler.h>

#ifndef arch_atomic_dec_return
static __always_inline int
arch_atomic_dec_return(atomic_t *v)
{
    return arch_atomic_sub_return(1, v);
}
#define arch_atomic_dec_return arch_atomic_dec_return
#endif

#ifndef arch_atomic_dec_and_test
/**
 * arch_atomic_dec_and_test - decrement and test
 * @v: pointer of type atomic_t
 *
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */
static __always_inline bool
arch_atomic_dec_and_test(atomic_t *v)
{
    return arch_atomic_dec_return(v) == 0;
}
#define arch_atomic_dec_and_test arch_atomic_dec_and_test
#endif

#ifndef arch_atomic_inc
static __always_inline void
arch_atomic_inc(atomic_t *v)
{
    arch_atomic_add(1, v);
}
#define arch_atomic_inc arch_atomic_inc
#endif

#ifndef arch_atomic_dec
static __always_inline void
arch_atomic_dec(atomic_t *v)
{
    arch_atomic_sub(1, v);
}
#define arch_atomic_dec arch_atomic_dec
#endif

#ifndef arch_atomic64_try_cmpxchg
static __always_inline bool
arch_atomic64_try_cmpxchg(atomic64_t *v, s64 *old, s64 new)
{
    s64 r, o = *old;
    r = arch_atomic64_cmpxchg(v, o, new);
    if (unlikely(r != o))
        *old = r;
    return likely(r == o);
}
#define arch_atomic64_try_cmpxchg arch_atomic64_try_cmpxchg
#endif

#ifndef arch_atomic64_try_cmpxchg_acquire
static __always_inline bool
arch_atomic64_try_cmpxchg_acquire(atomic64_t *v, s64 *old, s64 new)
{
    s64 r, o = *old;
    r = arch_atomic64_cmpxchg_acquire(v, o, new);
    if (unlikely(r != o))
        *old = r;
    return likely(r == o);
}
#define arch_atomic64_try_cmpxchg_acquire arch_atomic64_try_cmpxchg_acquire
#endif

#ifndef arch_atomic64_try_cmpxchg_release
static __always_inline bool
arch_atomic64_try_cmpxchg_release(atomic64_t *v, s64 *old, s64 new)
{
    s64 r, o = *old;
    r = arch_atomic64_cmpxchg_release(v, o, new);
    if (unlikely(r != o))
        *old = r;
    return likely(r == o);
}
#define arch_atomic64_try_cmpxchg_release arch_atomic64_try_cmpxchg_release
#endif

#ifndef arch_atomic64_try_cmpxchg_relaxed
static __always_inline bool
arch_atomic64_try_cmpxchg_relaxed(atomic64_t *v, s64 *old, s64 new)
{
    s64 r, o = *old;
    r = arch_atomic64_cmpxchg_relaxed(v, o, new);
    if (unlikely(r != o))
        *old = r;
    return likely(r == o);
}
#define arch_atomic64_try_cmpxchg_relaxed arch_atomic64_try_cmpxchg_relaxed
#endif

#ifndef arch_atomic64_andnot
static __always_inline void
arch_atomic64_andnot(s64 i, atomic64_t *v)
{
    arch_atomic64_and(~i, v);
}
#define arch_atomic64_andnot arch_atomic64_andnot
#endif

#ifndef arch_atomic64_inc
static __always_inline void
arch_atomic64_inc(atomic64_t *v)
{
    arch_atomic64_add(1, v);
}
#define arch_atomic64_inc arch_atomic64_inc
#endif

#ifndef arch_atomic64_dec
static __always_inline void
arch_atomic64_dec(atomic64_t *v)
{
    arch_atomic64_sub(1, v);
}
#define arch_atomic64_dec arch_atomic64_dec
#endif

#ifndef arch_atomic_inc_return
static __always_inline int
arch_atomic_inc_return(atomic_t *v)
{
    return arch_atomic_add_return(1, v);
}
#define arch_atomic_inc_return arch_atomic_inc_return
#endif

#ifndef arch_atomic_try_cmpxchg_relaxed
static __always_inline bool
arch_atomic_try_cmpxchg_relaxed(atomic_t *v, int *old, int new)
{
    int r, o = *old;
    r = arch_atomic_cmpxchg_relaxed(v, o, new);
    if (unlikely(r != o))
        *old = r;
    return likely(r == o);
}
#define arch_atomic_try_cmpxchg_relaxed arch_atomic_try_cmpxchg_relaxed
#endif

#ifndef arch_atomic_add_unless
/**
 * arch_atomic_add_unless - add unless the number is already a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, if @v was not already @u.
 * Returns true if the addition was done.
 */
static __always_inline bool
arch_atomic_add_unless(atomic_t *v, int a, int u)
{
    return arch_atomic_fetch_add_unless(v, a, u) != u;
}
#define arch_atomic_add_unless arch_atomic_add_unless
#endif

#ifndef arch_atomic_inc_not_zero
/**
 * arch_atomic_inc_not_zero - increment unless the number is zero
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1, if @v is non-zero.
 * Returns true if the increment was done.
 */
static __always_inline bool
arch_atomic_inc_not_zero(atomic_t *v)
{
    return arch_atomic_add_unless(v, 1, 0);
}
#define arch_atomic_inc_not_zero arch_atomic_inc_not_zero
#endif

#ifndef arch_atomic64_fetch_add_release
static __always_inline s64
arch_atomic64_fetch_add_release(s64 i, atomic64_t *v)
{
    __atomic_release_fence();
    return arch_atomic64_fetch_add_relaxed(i, v);
}
#define arch_atomic64_fetch_add_release arch_atomic64_fetch_add_release
#endif

#ifndef arch_atomic64_inc_return
static __always_inline s64
arch_atomic64_inc_return(atomic64_t *v)
{
    return arch_atomic64_add_return(1, v);
}
#define arch_atomic64_inc_return arch_atomic64_inc_return
#endif

#ifndef arch_atomic64_add_return_acquire
static __always_inline s64
arch_atomic64_add_return_acquire(s64 i, atomic64_t *v)
{
    s64 ret = arch_atomic64_add_return_relaxed(i, v);
    __atomic_acquire_fence();
    return ret;
}
#define arch_atomic64_add_return_acquire arch_atomic64_add_return_acquire
#endif

#ifndef arch_atomic64_add_return_release
static __always_inline s64
arch_atomic64_add_return_release(s64 i, atomic64_t *v)
{
    __atomic_release_fence();
    return arch_atomic64_add_return_relaxed(i, v);
}
#define arch_atomic64_add_return_release arch_atomic64_add_return_release
#endif

#ifndef arch_atomic_sub_and_test
/**
 * arch_atomic_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
static __always_inline bool
arch_atomic_sub_and_test(int i, atomic_t *v)
{
    return arch_atomic_sub_return(i, v) == 0;
}
#define arch_atomic_sub_and_test arch_atomic_sub_and_test
#endif

#ifndef arch_atomic64_sub_and_test
/**
 * arch_atomic64_sub_and_test - subtract value from variable and test result
 * @i: integer value to subtract
 * @v: pointer of type atomic64_t
 *
 * Atomically subtracts @i from @v and returns
 * true if the result is zero, or false for all
 * other cases.
 */
static __always_inline bool
arch_atomic64_sub_and_test(s64 i, atomic64_t *v)
{
    return arch_atomic64_sub_return(i, v) == 0;
}
#define arch_atomic64_sub_and_test arch_atomic64_sub_and_test
#endif

#ifndef arch_atomic64_add_unless
/**
 * arch_atomic64_add_unless - add unless the number is already a given value
 * @v: pointer of type atomic64_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, if @v was not already @u.
 * Returns true if the addition was done.
 */
static __always_inline bool
arch_atomic64_add_unless(atomic64_t *v, s64 a, s64 u)
{
    return arch_atomic64_fetch_add_unless(v, a, u) != u;
}
#define arch_atomic64_add_unless arch_atomic64_add_unless
#endif

#ifndef arch_atomic64_inc_not_zero
/**
 * arch_atomic64_inc_not_zero - increment unless the number is zero
 * @v: pointer of type atomic64_t
 *
 * Atomically increments @v by 1, if @v is non-zero.
 * Returns true if the increment was done.
 */
static __always_inline bool
arch_atomic64_inc_not_zero(atomic64_t *v)
{
    return arch_atomic64_add_unless(v, 1, 0);
}
#define arch_atomic64_inc_not_zero arch_atomic64_inc_not_zero
#endif

#ifndef arch_atomic_read_acquire
static __always_inline int
arch_atomic_read_acquire(const atomic_t *v)
{
    int ret;

    if (__native_word(atomic_t)) {
        ret = smp_load_acquire(&(v)->counter);
    } else {
        ret = arch_atomic_read(v);
        __atomic_acquire_fence();
    }

    return ret;
}
#define arch_atomic_read_acquire arch_atomic_read_acquire
#endif

#ifndef arch_atomic_try_cmpxchg
static __always_inline bool
arch_atomic_try_cmpxchg(atomic_t *v, int *old, int new)
{
    int r, o = *old;
    r = arch_atomic_cmpxchg(v, o, new);
    if (unlikely(r != o))
        *old = r;
    return likely(r == o);
}
#define arch_atomic_try_cmpxchg arch_atomic_try_cmpxchg
#endif

#ifndef arch_atomic_inc_unless_negative
static __always_inline bool
arch_atomic_inc_unless_negative(atomic_t *v)
{
    int c = arch_atomic_read(v);

    do {
        if (unlikely(c < 0))
            return false;
    } while (!arch_atomic_try_cmpxchg(v, &c, c + 1));

    return true;
}
#define arch_atomic_inc_unless_negative arch_atomic_inc_unless_negative
#endif

#ifndef arch_atomic_dec_unless_positive
static __always_inline bool
arch_atomic_dec_unless_positive(atomic_t *v)
{
    int c = arch_atomic_read(v);

    do {
        if (unlikely(c > 0))
            return false;
    } while (!arch_atomic_try_cmpxchg(v, &c, c - 1));

    return true;
}
#define arch_atomic_dec_unless_positive arch_atomic_dec_unless_positive
#endif

#ifndef arch_atomic_inc_and_test
/**
 * arch_atomic_inc_and_test - increment and test
 * @v: pointer of type atomic_t
 *
 * Atomically increments @v by 1
 * and returns true if the result is zero, or false for all
 * other cases.
 */
static __always_inline bool
arch_atomic_inc_and_test(atomic_t *v)
{
    return arch_atomic_inc_return(v) == 0;
}
#define arch_atomic_inc_and_test arch_atomic_inc_and_test
#endif

#endif /* _LINUX_ATOMIC_FALLBACK_H */

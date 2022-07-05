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

#endif /* _LINUX_ATOMIC_FALLBACK_H */

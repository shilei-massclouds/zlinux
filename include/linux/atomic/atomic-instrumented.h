// SPDX-License-Identifier: GPL-2.0

// Generated by scripts/atomic/gen-atomic-instrumented.sh
// DO NOT MODIFY THIS FILE DIRECTLY

/*
 * This file provides wrappers with KASAN instrumentation for atomic operations.
 * To use this functionality an arch's atomic.h file needs to define all
 * atomic operations with arch_ prefix (e.g. arch_atomic_read()) and include
 * this file at the end. This file provides atomic_read() that forwards to
 * arch_atomic_read() for actual atomic operation.
 * Note: if an arch atomic operation is implemented by means of other atomic
 * operations (e.g. atomic_read()/atomic_cmpxchg() loop), then it needs to use
 * arch_ variants (i.e. arch_atomic_read()/arch_atomic_cmpxchg()) to avoid
 * double instrumentation.
 */
#ifndef _LINUX_ATOMIC_INSTRUMENTED_H
#define _LINUX_ATOMIC_INSTRUMENTED_H

#include <linux/build_bug.h>
#include <linux/compiler.h>

#define cmpxchg(ptr, ...) \
({ \
    typeof(ptr) __ai_ptr = (ptr); \
    arch_cmpxchg(__ai_ptr, __VA_ARGS__); \
})

static __always_inline void
atomic_long_set(atomic_long_t *v, long i)
{
    arch_atomic_long_set(v, i);
}

static __always_inline long
atomic_long_read(const atomic_long_t *v)
{
    return arch_atomic_long_read(v);
}

static __always_inline void
atomic_long_add(long i, atomic_long_t *v)
{
    arch_atomic_long_add(i, v);
}

static __always_inline bool
atomic_dec_and_test(atomic_t *v)
{
    return arch_atomic_dec_and_test(v);
}

static __always_inline void
atomic_inc(atomic_t *v)
{
    arch_atomic_inc(v);
}

static __always_inline void
atomic_dec(atomic_t *v)
{
    arch_atomic_dec(v);
}

static __always_inline bool
atomic_long_try_cmpxchg_acquire(atomic_long_t *v, long *old, long new)
{
    return arch_atomic_long_try_cmpxchg_acquire(v, old, new);
}

static __always_inline bool
atomic_long_try_cmpxchg_release(atomic_long_t *v, long *old, long new)
{
    return arch_atomic_long_try_cmpxchg_release(v, old, new);
}

static __always_inline int
atomic_cmpxchg(atomic_t *v, int old, int new)
{
    return arch_atomic_cmpxchg(v, old, new);
}

static __always_inline void
atomic_long_or(long i, atomic_long_t *v)
{
    arch_atomic_long_or(i, v);
}

static __always_inline void
atomic_long_andnot(long i, atomic_long_t *v)
{
    arch_atomic_long_andnot(i, v);
}

static __always_inline int
atomic_fetch_add_relaxed(int i, atomic_t *v)
{
    return arch_atomic_fetch_add_relaxed(i, v);
}

#ifndef arch_atomic_fetch_sub_release
static __always_inline int
arch_atomic_fetch_sub_release(int i, atomic_t *v)
{
    __atomic_release_fence();
    return arch_atomic_fetch_sub_relaxed(i, v);
}
#define arch_atomic_fetch_sub_release arch_atomic_fetch_sub_release
#endif

static __always_inline int
atomic_fetch_sub_release(int i, atomic_t *v)
{
    return arch_atomic_fetch_sub_release(i, v);
}

#define cmpxchg_relaxed(ptr, ...) \
({ \
    typeof(ptr) __ai_ptr = (ptr); \
    arch_cmpxchg_relaxed(__ai_ptr, __VA_ARGS__); \
})

static __always_inline void
atomic_long_inc(atomic_long_t *v)
{
    arch_atomic_long_inc(v);
}

static __always_inline long
atomic_long_cmpxchg(atomic_long_t *v, long old, long new)
{
    return arch_atomic_long_cmpxchg(v, old, new);
}

static __always_inline long
atomic_long_cmpxchg_relaxed(atomic_long_t *v, long old, long new)
{
    return arch_atomic_long_cmpxchg_relaxed(v, old, new);
}

static __always_inline bool
atomic_long_try_cmpxchg(atomic_long_t *v, long *old, long new)
{
    return arch_atomic_long_try_cmpxchg(v, old, new);
}

static __always_inline long
atomic_long_xchg(atomic_long_t *v, long i)
{
    return arch_atomic_long_xchg(v, i);
}

static __always_inline long
atomic_long_add_return(long i, atomic_long_t *v)
{
    return arch_atomic_long_add_return(i, v);
}

#endif /* _LINUX_ATOMIC_INSTRUMENTED_H */

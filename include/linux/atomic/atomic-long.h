// SPDX-License-Identifier: GPL-2.0

// Generated by scripts/atomic/gen-atomic-long.sh
// DO NOT MODIFY THIS FILE DIRECTLY

#ifndef _LINUX_ATOMIC_LONG_H
#define _LINUX_ATOMIC_LONG_H

#include <linux/compiler.h>
#include <asm/types.h>

typedef atomic64_t atomic_long_t;
#define ATOMIC_LONG_INIT(i)     ATOMIC64_INIT(i)
#define atomic_long_cond_read_acquire   atomic64_cond_read_acquire
#define atomic_long_cond_read_relaxed   atomic64_cond_read_relaxed

static __always_inline void
arch_atomic_long_set(atomic_long_t *v, long i)
{
    arch_atomic64_set(v, i);
}

static __always_inline long
arch_atomic_long_read(const atomic_long_t *v)
{
    return arch_atomic64_read(v);
}

static __always_inline void
arch_atomic_long_add(long i, atomic_long_t *v)
{
    arch_atomic64_add(i, v);
}

static __always_inline bool
arch_atomic_long_try_cmpxchg_acquire(atomic_long_t *v, long *old, long new)
{
    return arch_atomic64_try_cmpxchg_acquire(v, (s64 *)old, new);
}

static __always_inline bool
arch_atomic_long_try_cmpxchg_release(atomic_long_t *v, long *old, long new)
{
    return arch_atomic64_try_cmpxchg_release(v, (s64 *)old, new);
}

static __always_inline void
arch_atomic_long_or(long i, atomic_long_t *v)
{
    arch_atomic64_or(i, v);
}

static __always_inline void
arch_atomic_long_andnot(long i, atomic_long_t *v)
{
    arch_atomic64_andnot(i, v);
}

#endif /* _LINUX_ATOMIC_LONG_H */

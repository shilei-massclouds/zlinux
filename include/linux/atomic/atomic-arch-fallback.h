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

#endif /* _LINUX_ATOMIC_FALLBACK_H */


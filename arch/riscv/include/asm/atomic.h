/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Copyright (C) 2012 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#ifndef _ASM_RISCV_ATOMIC_H
#define _ASM_RISCV_ATOMIC_H

#if (__riscv_xlen < 64)
# error "64-bit atomics require XLEN to be at least 64"
#endif

//#include <asm/cmpxchg.h>
//#include <asm/barrier.h>

/*
 * First, the atomic ops that have no ordering constraints and therefor don't
 * have the AQ or RL bits set.  These don't return anything, so there's only
 * one version to worry about.
 */
#define ATOMIC_OP(op, asm_op, I, asm_type, c_type, prefix)      \
static __always_inline                          \
void atomic##prefix##_##op(c_type i, atomic##prefix##_t *v)     \
{                                   \
    __asm__ __volatile__ (                      \
        "   amo" #asm_op "." #asm_type " zero, %1, %0"  \
        : "+A" (v->counter)                 \
        : "r" (I)                       \
        : "memory");                        \
}                                   \

#ifdef CONFIG_GENERIC_ATOMIC64
#define ATOMIC_OPS(op, asm_op, I)                   \
        ATOMIC_OP (op, asm_op, I, w, int,   )
#else
#define ATOMIC_OPS(op, asm_op, I)                   \
        ATOMIC_OP (op, asm_op, I, w, int,   )               \
        ATOMIC_OP (op, asm_op, I, d, s64, 64)
#endif

ATOMIC_OPS(add, add,  i)
ATOMIC_OPS(sub, add, -i)
ATOMIC_OPS(and, and,  i)
ATOMIC_OPS( or,  or,  i)
ATOMIC_OPS(xor, xor,  i)

#undef ATOMIC_OP
#undef ATOMIC_OPS

/*
 * Atomic ops that have ordered, relaxed, acquire, and release variants.
 * There's two flavors of these: the arithmatic ops have both fetch and return
 * versions, while the logical ops only have fetch versions.
 */
#define ATOMIC_FETCH_OP(op, asm_op, I, asm_type, c_type, prefix)    \
static __always_inline                          \
c_type atomic##prefix##_fetch_##op##_relaxed(c_type i,          \
                         atomic##prefix##_t *v) \
{                                   \
    register c_type ret;                        \
    __asm__ __volatile__ (                      \
        "   amo" #asm_op "." #asm_type " %1, %2, %0"    \
        : "+A" (v->counter), "=r" (ret)             \
        : "r" (I)                       \
        : "memory");                        \
    return ret;                         \
}                                   \
static __always_inline                          \
c_type atomic##prefix##_fetch_##op(c_type i, atomic##prefix##_t *v) \
{                                   \
    register c_type ret;                        \
    __asm__ __volatile__ (                      \
        "   amo" #asm_op "." #asm_type ".aqrl  %1, %2, %0"  \
        : "+A" (v->counter), "=r" (ret)             \
        : "r" (I)                       \
        : "memory");                        \
    return ret;                         \
}

#define ATOMIC_OP_RETURN(op, asm_op, c_op, I, asm_type, c_type, prefix) \
static __always_inline                          \
c_type atomic##prefix##_##op##_return_relaxed(c_type i,         \
                          atomic##prefix##_t *v)    \
{                                   \
    return atomic##prefix##_fetch_##op##_relaxed(i, v) c_op I;  \
}                                   \
static __always_inline                          \
c_type atomic##prefix##_##op##_return(c_type i, atomic##prefix##_t *v)  \
{                                   \
    return atomic##prefix##_fetch_##op(i, v) c_op I;        \
}

#define ATOMIC_OPS(op, asm_op, c_op, I) \
        ATOMIC_FETCH_OP( op, asm_op,       I, w, int,   )       \
        ATOMIC_OP_RETURN(op, asm_op, c_op, I, w, int,   )       \
        ATOMIC_FETCH_OP( op, asm_op,       I, d, s64, 64)       \
        ATOMIC_OP_RETURN(op, asm_op, c_op, I, d, s64, 64)

ATOMIC_OPS(add, add, +,  i)
ATOMIC_OPS(sub, add, +, -i)

#define atomic_add_return       atomic_add_return

#undef ATOMIC_OPS

#endif /* _ASM_RISCV_ATOMIC_H */

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2014 Regents of the University of California
 */

#ifndef _ASM_RISCV_CMPXCHG_H
#define _ASM_RISCV_CMPXCHG_H

#include <linux/bug.h>

#include <asm/barrier.h>
#include <asm/fence.h>

#define __cmpxchg(ptr, old, new, size)                  \
({                                  \
    __typeof__(ptr) __ptr = (ptr);                  \
    __typeof__(*(ptr)) __old = (old);               \
    __typeof__(*(ptr)) __new = (new);               \
    __typeof__(*(ptr)) __ret;                   \
    register unsigned int __rc;                 \
    switch (size) {                         \
    case 4:                             \
        __asm__ __volatile__ (                  \
            "0: lr.w %0, %2\n"              \
            "   bne  %0, %z3, 1f\n"         \
            "   sc.w.rl %1, %z4, %2\n"          \
            "   bnez %1, 0b\n"              \
            "   fence rw, rw\n"             \
            "1:\n"                      \
            : "=&r" (__ret), "=&r" (__rc), "+A" (*__ptr)    \
            : "rJ" ((long)__old), "rJ" (__new)      \
            : "memory");                    \
        break;                          \
    case 8:                             \
        __asm__ __volatile__ (                  \
            "0: lr.d %0, %2\n"              \
            "   bne %0, %z3, 1f\n"          \
            "   sc.d.rl %1, %z4, %2\n"          \
            "   bnez %1, 0b\n"              \
            "   fence rw, rw\n"             \
            "1:\n"                      \
            : "=&r" (__ret), "=&r" (__rc), "+A" (*__ptr)    \
            : "rJ" (__old), "rJ" (__new)            \
            : "memory");                    \
        break;                          \
    default:                            \
        BUILD_BUG();                        \
    }                               \
    __ret;                              \
})

#define arch_cmpxchg(ptr, o, n)                                         \
({                                                                      \
    __typeof__(*(ptr)) _o_ = (o);                                       \
    __typeof__(*(ptr)) _n_ = (n);                                       \
    (__typeof__(*(ptr))) __cmpxchg((ptr), _o_, _n_, sizeof(*(ptr)));    \
})

#endif /* _ASM_RISCV_CMPXCHG_H */

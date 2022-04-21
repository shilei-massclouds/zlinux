/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/include/asm/barrier.h
 *
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2013 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#ifndef _ASM_RISCV_BARRIER_H
#define _ASM_RISCV_BARRIER_H

#ifndef __ASSEMBLY__

#define nop()       __asm__ __volatile__ ("nop")

#define RISCV_FENCE(p, s) \
    __asm__ __volatile__ ("fence " #p "," #s : : : "memory")

#define __smp_store_release(p, v)                   \
do {                                    \
    compiletime_assert_atomic_type(*p);             \
    RISCV_FENCE(rw,w);                      \
    WRITE_ONCE(*p, v);                      \
} while (0)

#define __smp_load_acquire(p)                       \
({                                  \
    typeof(*p) ___p1 = READ_ONCE(*p);               \
    compiletime_assert_atomic_type(*p);             \
    RISCV_FENCE(r,rw);                      \
    ___p1;                              \
})

#include <asm-generic/barrier.h>

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_BARRIER_H */
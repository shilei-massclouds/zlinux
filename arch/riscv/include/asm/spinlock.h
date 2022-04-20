/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 Regents of the University of California
 * Copyright (C) 2017 SiFive
 */

#ifndef _ASM_RISCV_SPINLOCK_H
#define _ASM_RISCV_SPINLOCK_H

#include <linux/kernel.h>
#include <asm/current.h>
#include <asm/fence.h>

#define arch_spin_is_locked(x)  (READ_ONCE((x)->lock) != 0)

static inline void arch_spin_unlock(arch_spinlock_t *lock)
{
    smp_store_release(&lock->lock, 0);
}

static inline int arch_spin_trylock(arch_spinlock_t *lock)
{
    int tmp = 1, busy;

    __asm__ __volatile__ (
        "   amoswap.w %0, %2, %1\n"
        RISCV_ACQUIRE_BARRIER
        : "=r" (busy), "+A" (lock->lock)
        : "r" (tmp)
        : "memory");

    return !busy;
}

static inline void arch_spin_lock(arch_spinlock_t *lock)
{
    while (1) {
        if (arch_spin_is_locked(lock))
            continue;

        if (arch_spin_trylock(lock))
            break;
    }
}

#endif /* _ASM_RISCV_SPINLOCK_H */

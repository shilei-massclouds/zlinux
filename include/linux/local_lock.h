/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LOCAL_LOCK_H
#define _LINUX_LOCAL_LOCK_H

#include <linux/local_lock_internal.h>

/**
 * local_lock - Acquire a per CPU local lock
 * @lock:   The lock variable
 */
#define local_lock(lock) __local_lock(lock)

/**
 * local_unlock - Release a per CPU local lock
 * @lock:   The lock variable
 */
#define local_unlock(lock) __local_unlock(lock)

/**
 * local_lock_irqsave - Acquire a per CPU local lock, save and disable
 *           interrupts
 * @lock:   The lock variable
 * @flags:  Storage for interrupt flags
 */
#define local_lock_irqsave(lock, flags) \
    __local_lock_irqsave(lock, flags)

/**
 * local_unlock_irqrestore - Release a per CPU local lock and restore
 *                interrupt flags
 * @lock:   The lock variable
 * @flags:      Interrupt flags to restore
 */
#define local_unlock_irqrestore(lock, flags) \
    __local_unlock_irqrestore(lock, flags)

#endif /* _LINUX_LOCAL_LOCK_H */

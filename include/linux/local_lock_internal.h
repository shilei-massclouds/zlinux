/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LOCAL_LOCK_H
# error "Do not include directly, include linux/local_lock.h"
#endif

#include <linux/percpu-defs.h>

typedef struct {
} local_lock_t;

#define LOCAL_LOCK_DEBUG_INIT(lockname)
#define INIT_LOCAL_LOCK(lockname) { LOCAL_LOCK_DEBUG_INIT(lockname) }

static inline void local_lock_acquire(local_lock_t *l) { }
static inline void local_lock_release(local_lock_t *l) { }
static inline void local_lock_debug_init(local_lock_t *l) { }

#define __local_lock_irqsave(lock, flags)       \
    do {                                        \
        local_irq_save(flags);                  \
        local_lock_acquire(this_cpu_ptr(lock)); \
    } while (0)

#define __local_unlock_irqrestore(lock, flags)  \
    do {                                        \
        local_lock_release(this_cpu_ptr(lock)); \
        local_irq_restore(flags);               \
    } while (0)

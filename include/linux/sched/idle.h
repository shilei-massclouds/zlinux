/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_IDLE_H
#define _LINUX_SCHED_IDLE_H

#include <linux/sched.h>

enum cpu_idle_type {
    CPU_IDLE,
    CPU_NOT_IDLE,
    CPU_NEWLY_IDLE,
    CPU_MAX_IDLE_TYPES
};

static inline void __current_set_polling(void) { }
static inline void __current_clr_polling(void) { }

static inline bool __must_check current_set_polling_and_test(void)
{
    return unlikely(tif_need_resched());
}
static inline bool __must_check current_clr_polling_and_test(void)
{
    return unlikely(tif_need_resched());
}

#endif /* _LINUX_SCHED_IDLE_H */

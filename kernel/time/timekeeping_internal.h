/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _TIMEKEEPING_INTERNAL_H
#define _TIMEKEEPING_INTERNAL_H

#include <linux/clocksource.h>
#include <linux/spinlock.h>
#include <linux/time.h>

static inline u64 clocksource_delta(u64 now, u64 last, u64 mask)
{
    return (now - last) & mask;
}

#endif /* _TIMEKEEPING_INTERNAL_H */

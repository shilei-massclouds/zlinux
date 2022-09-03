/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TIMEKEEPING_H
#define _LINUX_TIMEKEEPING_H

#include <linux/errno.h>
#include <linux/clocksource_ids.h>

/* Included from linux/ktime.h */

/*
 * ktime_t based interfaces
 */

enum tk_offsets {
    TK_OFFS_REAL,
    TK_OFFS_BOOT,
    TK_OFFS_TAI,
    TK_OFFS_MAX,
};

void timekeeping_init(void);

extern ktime_t ktime_get(void);
extern ktime_t ktime_get_with_offset(enum tk_offsets offs);

/**
 * ktime_get_real - get the real (wall-) time in ktime_t format
 */
static inline ktime_t ktime_get_real(void)
{
    return ktime_get_with_offset(TK_OFFS_REAL);
}

/**
 * ktime_get_boottime - Returns monotonic time since boot in ktime_t format
 *
 * This is similar to CLOCK_MONTONIC/ktime_get, but also includes the
 * time spent in suspend.
 */
static inline ktime_t ktime_get_boottime(void)
{
    return ktime_get_with_offset(TK_OFFS_BOOT);
}

/**
 * ktime_get_clocktai - Returns the TAI time of day in ktime_t format
 */
static inline ktime_t ktime_get_clocktai(void)
{
    return ktime_get_with_offset(TK_OFFS_TAI);
}

static inline u64 ktime_get_ns(void)
{
    return ktime_to_ns(ktime_get());
}

static inline u64 ktime_get_boottime_ns(void)
{
    return ktime_to_ns(ktime_get_boottime());
}

#endif /* _LINUX_TIMEKEEPING_H */

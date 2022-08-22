/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TIME64_H
#define _LINUX_TIME64_H

#include <linux/math64.h>
#include <vdso/time64.h>

typedef __s64 time64_t;
typedef __u64 timeu64_t;

#include <uapi/linux/time.h>

/*
 * Limits for settimeofday():
 *
 * To prevent setting the time close to the wraparound point time setting
 * is limited so a reasonable uptime can be accomodated. Uptime of 30 years
 * should be really sufficient, which means the cutoff is 2232. At that
 * point the cutoff is just a small part of the larger problem.
 */
#define TIME_UPTIME_SEC_MAX     (30LL * 365 * 24 *3600)
#define TIME_SETTOD_SEC_MAX     (KTIME_SEC_MAX - TIME_UPTIME_SEC_MAX)

struct timespec64 {
    time64_t    tv_sec;         /* seconds */
    long        tv_nsec;        /* nanoseconds */
};

/* Located here for timespec[64]_valid_strict */
#define TIME64_MAX      ((s64)~((u64)1 << 63))
#define TIME64_MIN      (-TIME64_MAX - 1)

#define KTIME_MAX       ((s64)~((u64)1 << 63))
#define KTIME_MIN       (-KTIME_MAX - 1)
#define KTIME_SEC_MAX   (KTIME_MAX / NSEC_PER_SEC)
#define KTIME_SEC_MIN   (KTIME_MIN / NSEC_PER_SEC)

extern struct timespec64 ns_to_timespec64(const s64 nsec);

/**
 * timespec64_to_ns - Convert timespec64 to nanoseconds
 * @ts:     pointer to the timespec64 variable to be converted
 *
 * Returns the scalar nanosecond representation of the timespec64
 * parameter.
 */
static inline s64 timespec64_to_ns(const struct timespec64 *ts)
{
    /* Prevent multiplication overflow / underflow */
    if (ts->tv_sec >= KTIME_SEC_MAX)
        return KTIME_MAX;

    if (ts->tv_sec <= KTIME_SEC_MIN)
        return KTIME_MIN;

    return ((s64) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}

/*
 * Returns true if the timespec64 is norm, false if denorm:
 */
static inline bool timespec64_valid(const struct timespec64 *ts)
{
    /* Dates before 1970 are bogus */
    if (ts->tv_sec < 0)
        return false;
    /* Can't have more nanoseconds then a second */
    if ((unsigned long)ts->tv_nsec >= NSEC_PER_SEC)
        return false;
    return true;
}

static inline bool timespec64_valid_settod(const struct timespec64 *ts)
{
    if (!timespec64_valid(ts))
        return false;
    /* Disallow values which cause overflow issues vs. CLOCK_REALTIME */
    if ((unsigned long long)ts->tv_sec >= TIME_SETTOD_SEC_MAX)
        return false;
    return true;
}

/*
 * lhs < rhs:  return <0
 * lhs == rhs: return 0
 * lhs > rhs:  return >0
 */
static inline int timespec64_compare(const struct timespec64 *lhs,
                                     const struct timespec64 *rhs)
{
    if (lhs->tv_sec < rhs->tv_sec)
        return -1;
    if (lhs->tv_sec > rhs->tv_sec)
        return 1;
    return lhs->tv_nsec - rhs->tv_nsec;
}

extern void set_normalized_timespec64(struct timespec64 *ts, time64_t sec,
                                      s64 nsec);

/*
 * sub = lhs - rhs, in normalized form
 */
static inline struct timespec64 timespec64_sub(struct timespec64 lhs,
                                               struct timespec64 rhs)
{
    struct timespec64 ts_delta;
    set_normalized_timespec64(&ts_delta, lhs.tv_sec - rhs.tv_sec,
                              lhs.tv_nsec - rhs.tv_nsec);
    return ts_delta;
}

#endif /* _LINUX_TIME64_H */

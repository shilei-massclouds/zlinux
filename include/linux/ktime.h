/*
 *  include/linux/ktime.h
 *
 *  ktime_t - nanosecond-resolution time format.
 *
 *   Copyright(C) 2005, Thomas Gleixner <tglx@linutronix.de>
 *   Copyright(C) 2005, Red Hat, Inc., Ingo Molnar
 *
 *  data type definitions, declarations, prototypes and macros.
 *
 *  Started by: Thomas Gleixner and Ingo Molnar
 *
 *  Credits:
 *
 *      Roman Zippel provided the ideas and primary code snippets of
 *      the ktime_t union and further simplifications of the original
 *      code.
 *
 *  For licencing details see kernel-base/COPYING
 */
#ifndef _LINUX_KTIME_H
#define _LINUX_KTIME_H

#if 0
#include <linux/time.h>
#endif
#include <linux/jiffies.h>
#include <asm/bug.h>

/* Nanosecond scalar representation for kernel time values */
typedef s64 ktime_t;

//#include <vdso/ktime.h>

static inline ktime_t ns_to_ktime(u64 ns)
{
    return ns;
}

static inline ktime_t ms_to_ktime(u64 ms)
{
    return ms * NSEC_PER_MSEC;
}

/**
 * ktime_set - Set a ktime_t variable from a seconds/nanoseconds value
 * @secs:   seconds to set
 * @nsecs:  nanoseconds to set
 *
 * Return: The ktime_t representation of the value.
 */
static inline ktime_t ktime_set(const s64 secs, const unsigned long nsecs)
{
    if (unlikely(secs >= KTIME_SEC_MAX))
        return KTIME_MAX;

    return secs * NSEC_PER_SEC + (s64)nsecs;
}

/* convert a timespec64 to ktime_t format: */
static inline ktime_t timespec64_to_ktime(struct timespec64 ts)
{
    return ktime_set(ts.tv_sec, ts.tv_nsec);
}

/* Subtract two ktime_t variables. rem = lhs -rhs: */
#define ktime_sub(lhs, rhs) ((lhs) - (rhs))

/* Add two ktime_t variables. res = lhs + rhs: */
#define ktime_add(lhs, rhs) ((lhs) + (rhs))

/*
 * Add a ktime_t variable and a scalar nanosecond value.
 * res = kt + nsval:
 */
#define ktime_add_ns(kt, nsval)     ((kt) + (nsval))

/*
 * Subtract a scalar nanosecod from a ktime_t variable
 * res = kt - nsval:
 */
#define ktime_sub_ns(kt, nsval)     ((kt) - (nsval))

/*
 * Same as ktime_add(), but avoids undefined behaviour on overflow; however,
 * this means that you must check the result for overflow yourself.
 */
#define ktime_add_unsafe(lhs, rhs)  ((u64) (lhs) + (rhs))

/* Convert ktime_t to nanoseconds */
static inline s64 ktime_to_ns(const ktime_t kt)
{
    return kt;
}

extern ktime_t ktime_add_safe(const ktime_t lhs, const ktime_t rhs);

#include <linux/timekeeping.h>

#endif /* _LINUX_KTIME_H */

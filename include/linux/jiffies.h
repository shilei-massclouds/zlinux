/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_JIFFIES_H
#define _LINUX_JIFFIES_H

#include <linux/cache.h>
#include <linux/limits.h>
//#include <linux/math64.h>
#include <linux/minmax.h>
#include <linux/types.h>
/*
#include <linux/time.h>
#include <linux/timex.h>
#include <vdso/jiffies.h>
*/
#include <asm/param.h>          /* for HZ */
//#include <generated/timeconst.h>

/*
 * Have the 32 bit jiffies value wrap 5 minutes after boot
 * so jiffies wrap bugs show up earlier.
 */
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))

#ifndef __jiffy_arch_data
#define __jiffy_arch_data
#endif

/*
 * The 64-bit value is not atomic - you MUST NOT read it
 * without sampling the sequence number in jiffies_lock.
 * get_jiffies_64() will do this for you as appropriate.
 */
extern u64 __cacheline_aligned_in_smp jiffies_64;
extern unsigned long volatile __cacheline_aligned_in_smp __jiffy_arch_data jiffies;

/**
 * msecs_to_jiffies: - convert milliseconds to jiffies
 * @m:  time in milliseconds
 *
 * conversion is done as follows:
 *
 * - negative values mean 'infinite timeout' (MAX_JIFFY_OFFSET)
 *
 * - 'too large' values [that would result in larger than
 *   MAX_JIFFY_OFFSET values] mean 'infinite timeout' too.
 *
 * - all other values are converted to jiffies by either multiplying
 *   the input value by a factor or dividing it with a factor and
 *   handling any 32-bit overflows.
 *   for the details see __msecs_to_jiffies()
 *
 * msecs_to_jiffies() checks for the passed in value being a constant
 * via __builtin_constant_p() allowing gcc to eliminate most of the
 * code, __msecs_to_jiffies() is called if the value passed does not
 * allow constant folding and the actual conversion must be done at
 * runtime.
 * the HZ range specific helpers _msecs_to_jiffies() are called both
 * directly here and from __msecs_to_jiffies() in the case where
 * constant folding is not possible.
 */
#if 0
static __always_inline unsigned long msecs_to_jiffies(const unsigned int m)
{
    if (__builtin_constant_p(m)) {
        if ((int)m < 0)
            return MAX_JIFFY_OFFSET;
        return _msecs_to_jiffies(m);
    } else {
        return __msecs_to_jiffies(m);
    }
}
#endif

/*
 *  These inlines deal with timer wrapping correctly. You are
 *  strongly encouraged to use them
 *  1. Because people otherwise forget
 *  2. Because if the timer wrap changes in future you won't have to
 *     alter your driver code.
 *
 * time_after(a,b) returns true if the time a is after time b.
 *
 * Do this with "<0" and ">=0" to only test the sign of the result. A
 * good compiler would generate better code (and a really good compiler
 * wouldn't care). Gcc is currently neither.
 */
#define time_after(a,b) \
    (typecheck(unsigned long, a) && \
     typecheck(unsigned long, b) && \
     ((long)((b) - (a)) < 0))
#define time_before(a,b)    time_after(b,a)

#endif /* _LINUX_JIFFIES_H */

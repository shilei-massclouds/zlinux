// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  This file contains the interface functions for the various time related
 *  system calls: time, stime, gettimeofday, settimeofday, adjtime
 *
 * Modification history:
 *
 * 1993-09-02    Philip Gladstone
 *      Created file with time related functions from sched/core.c and adjtimex()
 * 1993-10-08    Torsten Duwe
 *      adjtime interface update and CMOS clock write code
 * 1995-08-13    Torsten Duwe
 *      kernel PLL updated to 1994-12-13 specs (rfc-1589)
 * 1999-01-16    Ulrich Windl
 *  Introduced error checking for many cases in adjtimex().
 *  Updated NTP code according to technical memorandum Jan '96
 *  "A Kernel Model for Precision Timekeeping" by Dave Mills
 *  Allow time_constant larger than MAXTC(6) for NTP v4 (MAXTC == 10)
 *  (Even though the technical memorandum forbids it)
 * 2004-07-14    Christoph Lameter
 *  Added getnstimeofday to allow the posix timer functions to return
 *  with nanosecond accuracy
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/timex.h>
//#include <linux/capability.h>
#include <linux/timekeeper_internal.h>
#include <linux/errno.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/math64.h>
#include <linux/ptrace.h>

#include <linux/uaccess.h>
#include <linux/compat.h>
#include <asm/unistd.h>

//#include <generated/timeconst.h>
//#include "timekeeping.h"

/**
 * ns_to_timespec64 - Convert nanoseconds to timespec64
 * @nsec:       the nanoseconds value to be converted
 *
 * Returns the timespec64 representation of the nsec parameter.
 */
struct timespec64 ns_to_timespec64(const s64 nsec)
{
    struct timespec64 ts = { 0, 0 };
    s32 rem;

    if (likely(nsec > 0)) {
        ts.tv_sec = div_u64_rem(nsec, NSEC_PER_SEC, &rem);
        ts.tv_nsec = rem;
    } else if (nsec < 0) {
        /*
         * With negative times, tv_sec points to the earlier
         * second, and tv_nsec counts the nanoseconds since
         * then, so tv_nsec is always a positive number.
         */
        ts.tv_sec = -div_u64_rem(-nsec - 1, NSEC_PER_SEC, &rem) - 1;
        ts.tv_nsec = NSEC_PER_SEC - rem - 1;
    }

    return ts;
}
EXPORT_SYMBOL(ns_to_timespec64);

/**
 * set_normalized_timespec - set timespec sec and nsec parts and normalize
 *
 * @ts:     pointer to timespec variable to be set
 * @sec:    seconds to set
 * @nsec:   nanoseconds to set
 *
 * Set seconds and nanoseconds field of a timespec variable and
 * normalize to the timespec storage format
 *
 * Note: The tv_nsec part is always in the range of
 *  0 <= tv_nsec < NSEC_PER_SEC
 * For negative values only the tv_sec field is negative !
 */
void set_normalized_timespec64(struct timespec64 *ts, time64_t sec, s64 nsec)
{
    while (nsec >= NSEC_PER_SEC) {
        /*
         * The following asm() prevents the compiler from
         * optimising this loop into a modulo operation. See
         * also __iter_div_u64_rem() in include/linux/time.h
         */
        asm("" : "+rm"(nsec));
        nsec -= NSEC_PER_SEC;
        ++sec;
    }
    while (nsec < 0) {
        asm("" : "+rm"(nsec));
        nsec += NSEC_PER_SEC;
        --sec;
    }
    ts->tv_sec = sec;
    ts->tv_nsec = nsec;
}
EXPORT_SYMBOL(set_normalized_timespec64);

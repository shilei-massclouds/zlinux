/*****************************************************************************
 *                                                                           *
 * Copyright (c) David L. Mills 1993                                         *
 *                                                                           *
 * Permission to use, copy, modify, and distribute this software and its     *
 * documentation for any purpose and without fee is hereby granted, provided *
 * that the above copyright notice appears in all copies and that both the   *
 * copyright notice and this permission notice appear in supporting          *
 * documentation, and that the name University of Delaware not be used in    *
 * advertising or publicity pertaining to distribution of the software       *
 * without specific, written prior permission.  The University of Delaware   *
 * makes no representations about the suitability this software for any      *
 * purpose.  It is provided "as is" without express or implied warranty.     *
 *                                                                           *
 *****************************************************************************/

#ifndef _LINUX_TIMEX_H
#define _LINUX_TIMEX_H

#include <uapi/linux/timex.h>

#define ADJ_ADJTIME     0x8000  /* switch between adjtime/adjtimex modes */
#define ADJ_OFFSET_SINGLESHOT   0x0001  /* old-fashioned adjtime */
#define ADJ_OFFSET_READONLY 0x2000  /* read-only adjtime */
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/param.h>

unsigned long random_get_entropy_fallback(void);

#define NTP_INTERVAL_FREQ  (HZ)
#define NTP_INTERVAL_LENGTH (NSEC_PER_SEC/NTP_INTERVAL_FREQ)

#define NTP_SCALE_SHIFT     32

#define MAXPHASE 500000000L /* max phase error (ns) */
#define MAXFREQ 500000      /* max frequency error (ns/s) */
#define MAXFREQ_SCALED ((s64)MAXFREQ << NTP_SCALE_SHIFT)
#define MINSEC 256      /* min interval between updates (s) */
#define MAXSEC 2048     /* max interval between updates (s) */
#define NTP_PHASE_LIMIT ((MAXPHASE / NSEC_PER_USEC) << 5) /* beyond max. dispersion */

/*
 * SHIFT_PLL is used as a dampening factor to define how much we
 * adjust the frequency correction for a given offset in PLL mode.
 * It also used in dampening the offset correction, to define how
 * much of the current value in time_offset we correct for each
 * second. Changing this value changes the stiffness of the ntp
 * adjustment code. A lower value makes it more flexible, reducing
 * NTP convergence time. A higher value makes it stiffer, increasing
 * convergence time, but making the clock more stable.
 *
 * In David Mills' nanokernel reference implementation SHIFT_PLL is 4.
 * However this seems to increase convergence time much too long.
 *
 * https://lists.ntp.org/pipermail/hackers/2008-January/003487.html
 *
 * In the above mailing list discussion, it seems the value of 4
 * was appropriate for other Unix systems with HZ=100, and that
 * SHIFT_PLL should be decreased as HZ increases. However, Linux's
 * clock steering implementation is HZ independent.
 *
 * Through experimentation, a SHIFT_PLL value of 2 was found to allow
 * for fast convergence (very similar to the NTPv3 code used prior to
 * v2.6.19), with good clock stability.
 *
 *
 * SHIFT_FLL is used as a dampening factor to define how much we
 * adjust the frequency correction for a given offset in FLL mode.
 * In David Mills' nanokernel reference implementation SHIFT_FLL is 2.
 *
 * MAXTC establishes the maximum time constant of the PLL.
 */
#define SHIFT_PLL   2   /* PLL frequency factor (shift) */
#define SHIFT_FLL   2   /* FLL frequency factor (shift) */
#define MAXTC       10  /* maximum time constant (shift) */

/* Required to safely shift negative values */
#define shift_right(x, s) ({    \
    __typeof__(x) __x = (x);    \
    __typeof__(s) __s = (s);    \
    __x < 0 ? -(-__x >> __s) : __x >> __s;  \
})

#include <asm/timex.h>

#endif /* LINUX_TIMEX_H */

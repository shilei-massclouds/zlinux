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

#include <asm/timex.h>

#endif /* LINUX_TIMEX_H */

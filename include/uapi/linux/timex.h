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

#ifndef _UAPI_LINUX_TIMEX_H
#define _UAPI_LINUX_TIMEX_H

#include <linux/time.h>

/*
 * Status codes (timex.status)
 */
#define STA_PLL     0x0001  /* enable PLL updates (rw) */
#define STA_PPSFREQ 0x0002  /* enable PPS freq discipline (rw) */
#define STA_PPSTIME 0x0004  /* enable PPS time discipline (rw) */
#define STA_FLL     0x0008  /* select frequency-lock mode (rw) */

#define STA_INS     0x0010  /* insert leap (rw) */
#define STA_DEL     0x0020  /* delete leap (rw) */
#define STA_UNSYNC  0x0040  /* clock unsynchronized (rw) */
#define STA_FREQHOLD    0x0080  /* hold frequency (rw) */

#define STA_PPSSIGNAL   0x0100  /* PPS signal present (ro) */
#define STA_PPSJITTER   0x0200  /* PPS signal jitter exceeded (ro) */
#define STA_PPSWANDER   0x0400  /* PPS signal wander exceeded (ro) */
#define STA_PPSERROR    0x0800  /* PPS signal calibration error (ro) */

#define STA_CLOCKERR    0x1000  /* clock hardware fault (ro) */
#define STA_NANO    0x2000  /* resolution (0 = us, 1 = ns) (ro) */
#define STA_MODE    0x4000  /* mode (0 = PLL, 1 = FLL) (ro) */
#define STA_CLK     0x8000  /* clock source (0 = A, 1 = B) (ro) */

/* read-only bits */
#define STA_RONLY (STA_PPSSIGNAL | STA_PPSJITTER | STA_PPSWANDER | \
    STA_PPSERROR | STA_CLOCKERR | STA_NANO | STA_MODE | STA_CLK)

/*
 * Clock states (time_state)
 */
#define TIME_OK     0   /* clock synchronized, no leap second */
#define TIME_INS    1   /* insert leap second */
#define TIME_DEL    2   /* delete leap second */
#define TIME_OOP    3   /* leap second in progress */
#define TIME_WAIT   4   /* leap second has occurred */
#define TIME_ERROR  5   /* clock not synchronized */
#define TIME_BAD    TIME_ERROR /* bw compat */

struct __kernel_timex_timeval {
    __kernel_time64_t   tv_sec;
    long long           tv_usec;
};

struct __kernel_timex {
    unsigned int modes; /* mode selector */
    int :32;            /* pad */
    long long offset;   /* time offset (usec) */
    long long freq; /* frequency offset (scaled ppm) */
    long long maxerror;/* maximum error (usec) */
    long long esterror;/* estimated error (usec) */
    int status;     /* clock command/status */
    int :32;            /* pad */
    long long constant;/* pll time constant */
    long long precision;/* clock precision (usec) (read only) */
    long long tolerance;/* clock frequency tolerance (ppm)
                   * (read only)
                   */
    struct __kernel_timex_timeval time; /* (read only, except for ADJ_SETOFFSET) */
    long long tick; /* (modified) usecs between clock ticks */

    long long ppsfreq;/* pps frequency (scaled ppm) (ro) */
    long long jitter; /* pps jitter (us) (ro) */
    int shift;              /* interval duration (s) (shift) (ro) */
    int :32;            /* pad */
    long long stabil;            /* pps stability (scaled ppm) (ro) */
    long long jitcnt; /* jitter limit exceeded (ro) */
    long long calcnt; /* calibration intervals (ro) */
    long long errcnt; /* calibration errors (ro) */
    long long stbcnt; /* stability limit exceeded (ro) */

    int tai;        /* TAI offset (ro) */

    int  :32; int  :32; int  :32; int  :32;
    int  :32; int  :32; int  :32; int  :32;
    int  :32; int  :32; int  :32;
};

#endif /* _UAPI_LINUX_TIMEX_H */

// SPDX-License-Identifier: GPL-2.0
/*
 * NTP state machine interfaces and logic.
 *
 * This code was mainly moved from kernel/timer.c and kernel/time.c
 * Please see those files for relevant copyright info and historical
 * changelogs.
 */

//#include <linux/capability.h>
#include <linux/clocksource.h>
//#include <linux/workqueue.h>
#include <linux/hrtimer.h>
#include <linux/jiffies.h>
#include <linux/math64.h>
#include <linux/timex.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/module.h>
//#include <linux/rtc.h>
//#include <linux/audit.h>

#include "ntp_internal.h"
#include "timekeeping_internal.h"

static u64          tick_length;
static u64          tick_length_base;

/*
 * phase-lock loop variables
 */

/*
 * clock synchronization status
 *
 * (TIME_ERROR prevents overwriting the CMOS clock)
 */
static int          time_state = TIME_OK;

/* clock status bits:                           */
static int          time_status = STA_UNSYNC;

/* time adjustment (nsecs):                     */
static s64          time_offset;

/* pll time constant:                           */
static long         time_constant = 2;

/* maximum error (usecs):                       */
static long         time_maxerror = NTP_PHASE_LIMIT;

/* estimated error (usecs):                     */
static long         time_esterror = NTP_PHASE_LIMIT;

/* frequency offset (scaled nsecs/secs):                */
static s64          time_freq;

/* time at last adjustment (secs):                  */
static time64_t     time_reftime;

static long         time_adjust;

/* constant (boot-param configurable) NTP tick adjustment (upscaled)    */
static s64          ntp_tick_adj;

/* second value of the next pending leapsecond, or TIME64_MAX if no leap */
static time64_t     ntp_next_leap_sec = TIME64_MAX;

static struct hrtimer sync_hrtimer;

#if 0
static inline s64 ntp_offset_chunk(s64 offset)
{
    return shift_right(offset, SHIFT_PLL + time_constant);
}
#endif

static inline void pps_reset_freq_interval(void) {}
static inline void pps_clear(void) {}
static inline void pps_dec_valid(void) {}
static inline void pps_set_freq(s64 freq) {}

static inline int is_error_status(int status)
{
    return status & (STA_UNSYNC|STA_CLOCKERR);
}

static inline void pps_fill_timex(struct __kernel_timex *txc)
{
    /* PPS is not implemented, so these are zero */
    txc->ppsfreq       = 0;
    txc->jitter    = 0;
    txc->shift     = 0;
    txc->stabil    = 0;
    txc->jitcnt    = 0;
    txc->calcnt    = 0;
    txc->errcnt    = 0;
    txc->stbcnt    = 0;
}

/**
 * ntp_clear - Clears the NTP state variables
 */
void ntp_clear(void)
{
    time_adjust = 0;        /* stop active adjtime() */
    time_status |= STA_UNSYNC;
    time_maxerror   = NTP_PHASE_LIMIT;
    time_esterror   = NTP_PHASE_LIMIT;

    ntp_update_frequency();

    tick_length = tick_length_base;
    time_offset = 0;

    ntp_next_leap_sec = TIME64_MAX;
    /* Clear PPS state variables */
    pps_clear();
}

u64 ntp_tick_length(void)
{
    return tick_length;
}

static enum hrtimer_restart sync_timer_callback(struct hrtimer *timer)
{
    //queue_work(system_freezable_power_efficient_wq, &sync_work);

    return HRTIMER_NORESTART;
}

static void __init ntp_init_cmos_sync(void)
{
    hrtimer_init(&sync_hrtimer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
    sync_hrtimer.function = sync_timer_callback;
}

void __init ntp_init(void)
{
    ntp_clear();
    ntp_init_cmos_sync();
}

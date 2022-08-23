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

#define SECS_PER_DAY        86400
#define MAX_TICKADJ         500LL       /* usecs */
#define MAX_TICKADJ_SCALED \
    (((MAX_TICKADJ * NSEC_PER_USEC) << NTP_SCALE_SHIFT) / NTP_INTERVAL_FREQ)
#define MAX_TAI_OFFSET      100000

/* USER_HZ period (usecs): */
unsigned long   tick_usec = USER_TICK_USEC;

/* SHIFTED_HZ period (nsecs): */
unsigned long   tick_nsec;

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

static inline s64 ntp_offset_chunk(s64 offset)
{
    return shift_right(offset, SHIFT_PLL + time_constant);
}

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

/*
 * Update (tick_length, tick_length_base, tick_nsec), based
 * on (tick_usec, ntp_tick_adj, time_freq):
 */
static void ntp_update_frequency(void)
{
    u64 second_length;
    u64 new_base;

    second_length       = (u64)(tick_usec * NSEC_PER_USEC * USER_HZ)
                            << NTP_SCALE_SHIFT;

    second_length       += ntp_tick_adj;
    second_length       += time_freq;

    tick_nsec           = div_u64(second_length, HZ) >> NTP_SCALE_SHIFT;
    new_base            = div_u64(second_length, NTP_INTERVAL_FREQ);

    /*
     * Don't wait for the next second_overflow, apply
     * the change to the tick length immediately:
     */
    tick_length         += new_base - tick_length_base;
    tick_length_base    = new_base;
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

/**
 * ntp_get_next_leap - Returns the next leapsecond in CLOCK_REALTIME ktime_t
 *
 * Provides the time of the next leapsecond against CLOCK_REALTIME in
 * a ktime_t format. Returns KTIME_MAX if no leapsecond is pending.
 */
ktime_t ntp_get_next_leap(void)
{
    ktime_t ret;

    if ((time_state == TIME_INS) && (time_status & STA_INS))
        return ktime_set(ntp_next_leap_sec, 0);
    ret = KTIME_MAX;
    return ret;
}

/*
 * this routine handles the overflow of the microsecond field
 *
 * The tricky bits of code to handle the accurate clock support
 * were provided by Dave Mills (Mills@UDEL.EDU) of NTP fame.
 * They were originally developed for SUN and DEC kernels.
 * All the kudos should go to Dave for this stuff.
 *
 * Also handles leap second processing, and returns leap offset
 */
int second_overflow(time64_t secs)
{
    s64 delta;
    int leap = 0;
    s32 rem;

    /*
     * Leap second processing. If in leap-insert state at the end of the
     * day, the system clock is set back one second; if in leap-delete
     * state, the system clock is set ahead one second.
     */
    switch (time_state) {
    case TIME_OK:
        if (time_status & STA_INS) {
            time_state = TIME_INS;
            div_s64_rem(secs, SECS_PER_DAY, &rem);
            ntp_next_leap_sec = secs + SECS_PER_DAY - rem;
        } else if (time_status & STA_DEL) {
            time_state = TIME_DEL;
            div_s64_rem(secs + 1, SECS_PER_DAY, &rem);
            ntp_next_leap_sec = secs + SECS_PER_DAY - rem;
        }
        break;
    case TIME_INS:
        if (!(time_status & STA_INS)) {
            ntp_next_leap_sec = TIME64_MAX;
            time_state = TIME_OK;
        } else if (secs == ntp_next_leap_sec) {
            leap = -1;
            time_state = TIME_OOP;
            printk(KERN_NOTICE
                   "Clock: inserting leap second 23:59:60 UTC\n");
        }
        break;
    case TIME_DEL:
        if (!(time_status & STA_DEL)) {
            ntp_next_leap_sec = TIME64_MAX;
            time_state = TIME_OK;
        } else if (secs == ntp_next_leap_sec) {
            leap = 1;
            ntp_next_leap_sec = TIME64_MAX;
            time_state = TIME_WAIT;
            printk(KERN_NOTICE
                   "Clock: deleting leap second 23:59:59 UTC\n");
        }
        break;
    case TIME_OOP:
        ntp_next_leap_sec = TIME64_MAX;
        time_state = TIME_WAIT;
        break;
    case TIME_WAIT:
        if (!(time_status & (STA_INS | STA_DEL)))
            time_state = TIME_OK;
        break;
    }

    /* Bump the maxerror field */
    time_maxerror += MAXFREQ / NSEC_PER_USEC;
    if (time_maxerror > NTP_PHASE_LIMIT) {
        time_maxerror = NTP_PHASE_LIMIT;
        time_status |= STA_UNSYNC;
    }

    /* Compute the phase adjustment for the next second */
    tick_length  = tick_length_base;

    delta        = ntp_offset_chunk(time_offset);
    time_offset -= delta;
    tick_length += delta;

    /* Check PPS signal */
    pps_dec_valid();

    if (!time_adjust)
        goto out;

    panic("%s: END!\n", __func__);
    time_adjust = 0;

 out:
    return leap;
}

void __init ntp_init(void)
{
    ntp_clear();
    ntp_init_cmos_sync();
}

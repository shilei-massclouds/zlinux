// SPDX-License-Identifier: GPL-2.0
/*
 *  Kernel timekeeping code and accessor functions. Based on code from
 *  timer.c, moved in commit 8524070b7982.
 */
#include <linux/timekeeper_internal.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/init.h>
#include <linux/mm.h>
//#include <linux/nmi.h>
#include <linux/sched.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/clock.h>
//#include <linux/syscore_ops.h>
#include <linux/clocksource.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/tick.h>
#include <linux/stop_machine.h>
//#include <linux/pvclock_gtod.h>
#include <linux/compiler.h>
//#include <linux/audit.h>

#include "tick-internal.h"
#include "ntp_internal.h"
#include "timekeeping_internal.h"

#define TK_CLEAR_NTP        (1 << 0)
#define TK_MIRROR           (1 << 1)
#define TK_CLOCK_WAS_SET    (1 << 2)

enum timekeeping_adv_mode {
    /* Update timekeeper when a tick has passed */
    TK_ADV_TICK,

    /* Update timekeeper on a direct frequency change */
    TK_ADV_FREQ
};

DEFINE_RAW_SPINLOCK(timekeeper_lock);

/* Flag for if there is a persistent clock on this platform */
static bool persistent_clock_exists;

/* flag for if timekeeping is suspended */
int __read_mostly timekeeping_suspended;

/*
 * The most important data for readout fits into a single 64 byte
 * cache line.
 */
static struct {
    seqcount_raw_spinlock_t seq;
    struct timekeeper   timekeeper;
} tk_core ____cacheline_aligned = {
    .seq = SEQCNT_RAW_SPINLOCK_ZERO(tk_core.seq, &timekeeper_lock),
};

static struct timekeeper shadow_timekeeper;

/*
 * tk_clock_read - atomic clocksource read() helper
 *
 * This helper is necessary to use in the read paths because, while the
 * seqcount ensures we don't return a bad value while structures are updated,
 * it doesn't protect from potential crashes. There is the possibility that
 * the tkr's clocksource may change between the read reference, and the
 * clock reference passed to the read function.  This can cause crashes if
 * the wrong clocksource is passed to the wrong read function.
 * This isn't necessary to use when holding the timekeeper_lock or doing
 * a read of the fast-timekeeper tkrs (which is protected by its own locking
 * and update logic).
 */
static inline u64 tk_clock_read(const struct tk_read_base *tkr)
{
    struct clocksource *clock = READ_ONCE(tkr->clock);

    return clock->read(clock);
}

static inline void timekeeping_check_update(struct timekeeper *tk, u64 offset)
{
}

static inline u64 timekeeping_get_delta(const struct tk_read_base *tkr)
{
    u64 cycle_now, delta;

    /* read clocksource */
    cycle_now = tk_clock_read(tkr);

    /* calculate the delta since the last update_wall_time */
    delta = clocksource_delta(cycle_now, tkr->cycle_last, tkr->mask);

    return delta;
}

static inline u64 timekeeping_delta_to_ns(const struct tk_read_base *tkr,
                                          u64 delta)
{
    u64 nsec;

    nsec = delta * tkr->mult + tkr->xtime_nsec;
    nsec >>= tkr->shift;

    return nsec;
}

static inline u64 timekeeping_get_ns(const struct tk_read_base *tkr)
{
    u64 delta;

    delta = timekeeping_get_delta(tkr);
    return timekeeping_delta_to_ns(tkr, delta);
}

ktime_t ktime_get(void)
{
    struct timekeeper *tk = &tk_core.timekeeper;
    unsigned int seq;
    ktime_t base;
    u64 nsecs;

    WARN_ON(timekeeping_suspended);

    do {
        seq = read_seqcount_begin(&tk_core.seq);
        base = tk->tkr_mono.base;
        nsecs = timekeeping_get_ns(&tk->tkr_mono);

    } while (read_seqcount_retry(&tk_core.seq, seq));

    return ktime_add_ns(base, nsecs);
}
EXPORT_SYMBOL_GPL(ktime_get);

/**
 * read_persistent_clock64 -  Return time from the persistent clock.
 * @ts: Pointer to the storage for the readout value
 *
 * Weak dummy function for arches that do not yet support it.
 * Reads the time from the battery backed persistent clock.
 * Returns a timespec with tv_sec=0 and tv_nsec=0 if unsupported.
 *
 *  XXX - Do be sure to remove it once all arches implement it.
 */
void __weak read_persistent_clock64(struct timespec64 *ts)
{
    ts->tv_sec = 0;
    ts->tv_nsec = 0;
}

/**
 * read_persistent_wall_and_boot_offset - Read persistent clock, and also offset
 *                                        from the boot.
 *
 * Weak dummy function for arches that do not yet support it.
 * @wall_time:  - current time as returned by persistent clock
 * @boot_offset: - offset that is defined as wall_time - boot_time
 *
 * The default function calculates offset based on the current value of
 * local_clock(). This way architectures that support sched_clock() but don't
 * support dedicated boot time clock will provide the best estimate of the
 * boot time.
 */
void __weak __init
read_persistent_wall_and_boot_offset(struct timespec64 *wall_time,
                                     struct timespec64 *boot_offset)
{
    read_persistent_clock64(wall_time);
    *boot_offset = ns_to_timespec64(local_clock());
}

/**
 * tk_setup_internals - Set up internals to use clocksource clock.
 *
 * @tk:     The target timekeeper to setup.
 * @clock:      Pointer to clocksource.
 *
 * Calculates a fixed cycle/nsec interval for a given clocksource/adjustment
 * pair and interval request.
 *
 * Unless you're the timekeeping code, you should not be using this!
 */
static void tk_setup_internals(struct timekeeper *tk, struct clocksource *clock)
{
    u64 interval;
    u64 tmp, ntpinterval;
    struct clocksource *old_clock;

    ++tk->cs_was_changed_seq;
    old_clock = tk->tkr_mono.clock;
    tk->tkr_mono.clock = clock;
    tk->tkr_mono.mask = clock->mask;
    tk->tkr_mono.cycle_last = tk_clock_read(&tk->tkr_mono);

    tk->tkr_raw.clock = clock;
    tk->tkr_raw.mask = clock->mask;
    tk->tkr_raw.cycle_last = tk->tkr_mono.cycle_last;

    /* Do the ns -> cycle conversion first, using original mult */
    tmp = NTP_INTERVAL_LENGTH;
    tmp <<= clock->shift;
    ntpinterval = tmp;
    tmp += clock->mult/2;
    do_div(tmp, clock->mult);
    if (tmp == 0)
        tmp = 1;

    interval = (u64) tmp;
    tk->cycle_interval = interval;

    /* Go back from cycles -> shifted ns */
    tk->xtime_interval = interval * clock->mult;
    tk->xtime_remainder = ntpinterval - tk->xtime_interval;
    tk->raw_interval = interval * clock->mult;

    /* if changing clocks, convert xtime_nsec shift units */
    if (old_clock) {
        int shift_change = clock->shift - old_clock->shift;
        if (shift_change < 0) {
            tk->tkr_mono.xtime_nsec >>= -shift_change;
            tk->tkr_raw.xtime_nsec >>= -shift_change;
        } else {
            tk->tkr_mono.xtime_nsec <<= shift_change;
            tk->tkr_raw.xtime_nsec <<= shift_change;
        }
    }

    tk->tkr_mono.shift = clock->shift;
    tk->tkr_raw.shift = clock->shift;

    tk->ntp_error = 0;
    tk->ntp_error_shift = NTP_SCALE_SHIFT - clock->shift;
    tk->ntp_tick = ntpinterval << tk->ntp_error_shift;

    /*
     * The timekeeper keeps its own mult values for the currently
     * active clocksource. These value will be adjusted via NTP
     * to counteract clock drifting.
     */
    tk->tkr_mono.mult = clock->mult;
    tk->tkr_raw.mult = clock->mult;
    tk->ntp_err_mult = 0;
    tk->skip_second_overflow = 0;
}

static void tk_set_xtime(struct timekeeper *tk, const struct timespec64 *ts)
{
    tk->xtime_sec = ts->tv_sec;
    tk->tkr_mono.xtime_nsec = (u64)ts->tv_nsec << tk->tkr_mono.shift;
}

static void tk_set_wall_to_mono(struct timekeeper *tk, struct timespec64 wtm)
{
    struct timespec64 tmp;

    /*
     * Verify consistency of: offset_real = -wall_to_monotonic
     * before modifying anything
     */
    set_normalized_timespec64(&tmp, -tk->wall_to_monotonic.tv_sec,
                              -tk->wall_to_monotonic.tv_nsec);
    WARN_ON_ONCE(tk->offs_real != timespec64_to_ktime(tmp));
    tk->wall_to_monotonic = wtm;
    set_normalized_timespec64(&tmp, -wtm.tv_sec, -wtm.tv_nsec);
    tk->offs_real = timespec64_to_ktime(tmp);
    tk->offs_tai = ktime_add(tk->offs_real, ktime_set(tk->tai_offset, 0));
}

/*
 * tk_update_leap_state - helper to update the next_leap_ktime
 */
static inline void tk_update_leap_state(struct timekeeper *tk)
{
#if 0
    tk->next_leap_ktime = ntp_get_next_leap();
    if (tk->next_leap_ktime != KTIME_MAX)
        /* Convert to monotonic time */
        tk->next_leap_ktime = ktime_sub(tk->next_leap_ktime, tk->offs_real);
#endif
    panic("%s: END!\n", __func__);
}

/* must hold timekeeper_lock */
static void timekeeping_update(struct timekeeper *tk, unsigned int action)
{
    if (action & TK_CLEAR_NTP) {
        tk->ntp_error = 0;
        //ntp_clear();
    }

    //tk_update_leap_state(tk);
    //tk_update_ktime_data(tk);

    panic("%s: END!\n", __func__);
}

/*
 * timekeeping_init - Initializes the clocksource and common timekeeping values
 */
void __init timekeeping_init(void)
{
    struct timespec64 wall_time, boot_offset, wall_to_mono;
    struct timekeeper *tk = &tk_core.timekeeper;
    struct clocksource *clock;
    unsigned long flags;

    read_persistent_wall_and_boot_offset(&wall_time, &boot_offset);
    if (timespec64_valid_settod(&wall_time) &&
        timespec64_to_ns(&wall_time) > 0) {
        persistent_clock_exists = true;
    } else if (timespec64_to_ns(&wall_time) != 0) {
        pr_warn("Persistent clock returned invalid value");
        wall_time = (struct timespec64){0};
    }

    if (timespec64_compare(&wall_time, &boot_offset) < 0)
        boot_offset = (struct timespec64){0};

    /*
     * We want set wall_to_mono, so the following is true:
     * wall time + wall_to_mono = boot time
     */
    wall_to_mono = timespec64_sub(boot_offset, wall_time);

    raw_spin_lock_irqsave(&timekeeper_lock, flags);
    write_seqcount_begin(&tk_core.seq);
    ntp_init();

    clock = clocksource_default_clock();
    if (clock->enable)
        clock->enable(clock);
    tk_setup_internals(tk, clock);

    tk_set_xtime(tk, &wall_time);
    tk->raw_sec = 0;

    tk_set_wall_to_mono(tk, wall_to_mono);

    //timekeeping_update(tk, TK_MIRROR | TK_CLOCK_WAS_SET);

    write_seqcount_end(&tk_core.seq);
    raw_spin_unlock_irqrestore(&timekeeper_lock, flags);
}

/*
 * logarithmic_accumulation - shifted accumulation of cycles
 *
 * This functions accumulates a shifted interval of cycles into
 * a shifted interval nanoseconds. Allows for O(log) accumulation
 * loop.
 *
 * Returns the unconsumed cycles.
 */
static u64 logarithmic_accumulation(struct timekeeper *tk, u64 offset,
                                    u32 shift, unsigned int *clock_set)
{
    panic("%s: END!\n", __func__);
}

/*
 * timekeeping_advance - Updates the timekeeper to the current time and
 * current NTP tick length
 */
static bool timekeeping_advance(enum timekeeping_adv_mode mode)
{
    struct timekeeper *real_tk = &tk_core.timekeeper;
    struct timekeeper *tk = &shadow_timekeeper;
    u64 offset;
    int shift = 0, maxshift;
    unsigned int clock_set = 0;
    unsigned long flags;

    raw_spin_lock_irqsave(&timekeeper_lock, flags);

    /* Make sure we're fully resumed: */
    if (unlikely(timekeeping_suspended))
        goto out;

    offset = clocksource_delta(tk_clock_read(&tk->tkr_mono),
                   tk->tkr_mono.cycle_last, tk->tkr_mono.mask);

    /* Check if there's really nothing to do */
    if (offset < real_tk->cycle_interval && mode == TK_ADV_TICK)
        goto out;

    /* Do some additional sanity checking */
    timekeeping_check_update(tk, offset);

    /*
     * With NO_HZ we may have to accumulate many cycle_intervals
     * (think "ticks") worth of time at once. To do this efficiently,
     * we calculate the largest doubling multiple of cycle_intervals
     * that is smaller than the offset.  We then accumulate that
     * chunk in one go, and then try to consume the next smaller
     * doubled multiple.
     */
    shift = ilog2(offset) - ilog2(tk->cycle_interval);
    shift = max(0, shift);
    /* Bound shift to one less than what overflows tick_length */
    maxshift = (64 - (ilog2(ntp_tick_length())+1)) - 1;
    shift = min(shift, maxshift);
    while (offset >= tk->cycle_interval) {
        offset = logarithmic_accumulation(tk, offset, shift, &clock_set);
        if (offset < tk->cycle_interval<<shift)
            shift--;
    }

    panic("%s: END!\n", __func__);

 out:
    raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

    return !!clock_set;
}

/**
 * update_wall_time - Uses the current clocksource to increment the wall time
 *
 */
void update_wall_time(void)
{
    if (timekeeping_advance(TK_ADV_TICK))
        clock_was_set_delayed();
}

/*
 * Must hold jiffies_lock
 */
void do_timer(unsigned long ticks)
{
    jiffies_64 += ticks;
    //calc_global_load();
}

static ktime_t *offsets[TK_OFFS_MAX] = {
    [TK_OFFS_REAL]  = &tk_core.timekeeper.offs_real,
    [TK_OFFS_BOOT]  = &tk_core.timekeeper.offs_boot,
    [TK_OFFS_TAI]   = &tk_core.timekeeper.offs_tai,
};

ktime_t ktime_get_with_offset(enum tk_offsets offs)
{
    struct timekeeper *tk = &tk_core.timekeeper;
    unsigned int seq;
    ktime_t base, *offset = offsets[offs];
    u64 nsecs;

    WARN_ON(timekeeping_suspended);

    do {
        seq = read_seqcount_begin(&tk_core.seq);
        base = ktime_add(tk->tkr_mono.base, *offset);
        nsecs = timekeeping_get_ns(&tk->tkr_mono);

    } while (read_seqcount_retry(&tk_core.seq, seq));

    return ktime_add_ns(base, nsecs);
}
EXPORT_SYMBOL_GPL(ktime_get_with_offset);

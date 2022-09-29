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

/* Suspend-time cycles value for halted fast timekeeper. */
static u64 cycles_at_suspend;

static u64 dummy_clock_read(struct clocksource *cs)
{
    if (timekeeping_suspended)
        return cycles_at_suspend;
    return local_clock();
}

static struct clocksource dummy_clock = {
    .read = dummy_clock_read,
};

/**
 * struct tk_fast - NMI safe timekeeper
 * @seq:    Sequence counter for protecting updates. The lowest bit
 *      is the index for the tk_read_base array
 * @base:   tk_read_base array. Access is indexed by the lowest bit of
 *      @seq.
 *
 * See @update_fast_timekeeper() below.
 */
struct tk_fast {
    seqcount_latch_t    seq;
    struct tk_read_base base[2];
};

/*
 * Boot time initialization which allows local_clock() to be utilized
 * during early boot when clocksources are not available. local_clock()
 * returns nanoseconds already so no conversion is required, hence mult=1
 * and shift=0. When the first proper clocksource is installed then
 * the fast time keepers are updated with the correct values.
 */
#define FAST_TK_INIT                        \
    {                           \
        .clock      = &dummy_clock,         \
        .mask       = CLOCKSOURCE_MASK(64),     \
        .mult       = 1,                \
        .shift      = 0,                \
    }

static struct tk_fast tk_fast_mono ____cacheline_aligned = {
    .seq     = SEQCNT_LATCH_ZERO(tk_fast_mono.seq),
    .base[0] = FAST_TK_INIT,
    .base[1] = FAST_TK_INIT,
};

static struct tk_fast tk_fast_raw  ____cacheline_aligned = {
    .seq     = SEQCNT_LATCH_ZERO(tk_fast_raw.seq),
    .base[0] = FAST_TK_INIT,
    .base[1] = FAST_TK_INIT,
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
    tk->next_leap_ktime = ntp_get_next_leap();
    if (tk->next_leap_ktime != KTIME_MAX)
        /* Convert to monotonic time */
        tk->next_leap_ktime = ktime_sub(tk->next_leap_ktime,
                                        tk->offs_real);
}

/*
 * Update the ktime_t based scalar nsec members of the timekeeper
 */
static inline void tk_update_ktime_data(struct timekeeper *tk)
{
    u64 seconds;
    u32 nsec;

    /*
     * The xtime based monotonic readout is:
     *  nsec = (xtime_sec + wtm_sec) * 1e9 + wtm_nsec + now();
     * The ktime based monotonic readout is:
     *  nsec = base_mono + now();
     * ==> base_mono = (xtime_sec + wtm_sec) * 1e9 + wtm_nsec
     */
    seconds = (u64)(tk->xtime_sec + tk->wall_to_monotonic.tv_sec);
    nsec = (u32) tk->wall_to_monotonic.tv_nsec;
    tk->tkr_mono.base = ns_to_ktime(seconds * NSEC_PER_SEC + nsec);

    /*
     * The sum of the nanoseconds portions of xtime and
     * wall_to_monotonic can be greater/equal one second. Take
     * this into account before updating tk->ktime_sec.
     */
    nsec += (u32)(tk->tkr_mono.xtime_nsec >> tk->tkr_mono.shift);
    if (nsec >= NSEC_PER_SEC)
        seconds++;
    tk->ktime_sec = seconds;

    /* Update the monotonic raw base */
    tk->tkr_raw.base = ns_to_ktime(tk->raw_sec * NSEC_PER_SEC);
}

/**
 * update_fast_timekeeper - Update the fast and NMI safe monotonic timekeeper.
 * @tkr: Timekeeping readout base from which we take the update
 * @tkf: Pointer to NMI safe timekeeper
 *
 * We want to use this from any context including NMI and tracing /
 * instrumenting the timekeeping code itself.
 *
 * Employ the latch technique; see @raw_write_seqcount_latch.
 *
 * So if a NMI hits the update of base[0] then it will use base[1]
 * which is still consistent. In the worst case this can result is a
 * slightly wrong timestamp (a few nanoseconds). See
 * @ktime_get_mono_fast_ns.
 */
static void update_fast_timekeeper(const struct tk_read_base *tkr,
                                   struct tk_fast *tkf)
{
    struct tk_read_base *base = tkf->base;

    /* Force readers off to base[1] */
    raw_write_seqcount_latch(&tkf->seq);

    /* Update base[0] */
    memcpy(base, tkr, sizeof(*base));

    /* Force readers back to base[0] */
    raw_write_seqcount_latch(&tkf->seq);

    /* Update base[1] */
    memcpy(base + 1, base, sizeof(*base));
}

/* must hold timekeeper_lock */
static void timekeeping_update(struct timekeeper *tk,
                               unsigned int action)
{
    if (action & TK_CLEAR_NTP) {
        tk->ntp_error = 0;
        ntp_clear();
    }

    tk_update_leap_state(tk);
    tk_update_ktime_data(tk);

    //update_vsyscall(tk);
    //update_pvclock_gtod(tk, action & TK_CLOCK_WAS_SET);

    tk->tkr_mono.base_real = tk->tkr_mono.base + tk->offs_real;
    update_fast_timekeeper(&tk->tkr_mono, &tk_fast_mono);
    update_fast_timekeeper(&tk->tkr_raw,  &tk_fast_raw);

    if (action & TK_CLOCK_WAS_SET)
        tk->clock_was_set_seq++;

    /*
     * The mirroring of the data to the shadow-timekeeper needs
     * to happen last here to ensure we don't over-write the
     * timekeeper structure on the next update with stale data
     */
    if (action & TK_MIRROR)
        memcpy(&shadow_timekeeper, &tk_core.timekeeper,
               sizeof(tk_core.timekeeper));
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

    timekeeping_update(tk, TK_MIRROR | TK_CLOCK_WAS_SET);

    write_seqcount_end(&tk_core.seq);
    raw_spin_unlock_irqrestore(&timekeeper_lock, flags);
}

/*
 * accumulate_nsecs_to_secs - Accumulates nsecs into secs
 *
 * Helper function that accumulates the nsecs greater than a second
 * from the xtime_nsec field to the xtime_secs field.
 * It also calls into the NTP code to handle leapsecond processing.
 */
static inline
unsigned int accumulate_nsecs_to_secs(struct timekeeper *tk)
{
    u64 nsecps = (u64)NSEC_PER_SEC << tk->tkr_mono.shift;
    unsigned int clock_set = 0;

    while (tk->tkr_mono.xtime_nsec >= nsecps) {
        int leap;

        tk->tkr_mono.xtime_nsec -= nsecps;
        tk->xtime_sec++;

        /*
         * Skip NTP update if this second was accumulated before,
         * i.e. xtime_nsec underflowed in timekeeping_adjust()
         */
        if (unlikely(tk->skip_second_overflow)) {
            tk->skip_second_overflow = 0;
            continue;
        }

        /* Figure out if its a leap sec and apply if needed */
        leap = second_overflow(tk->xtime_sec);
        if (unlikely(leap)) {
#if 0
            struct timespec64 ts;

            tk->xtime_sec += leap;

            ts.tv_sec = leap;
            ts.tv_nsec = 0;
            tk_set_wall_to_mono(tk,
                timespec64_sub(tk->wall_to_monotonic, ts));

            __timekeeping_set_tai_offset(tk, tk->tai_offset - leap);

            clock_set = TK_CLOCK_WAS_SET;
#endif
            panic("%s: END!\n", __func__);
        }
    }
    return clock_set;
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
    u64 interval = tk->cycle_interval << shift;
    u64 snsec_per_sec;

    /* If the offset is smaller than a shifted interval, do nothing */
    if (offset < interval)
        return offset;

    /* Accumulate one shifted interval */
    offset -= interval;
    tk->tkr_mono.cycle_last += interval;
    tk->tkr_raw.cycle_last  += interval;

    tk->tkr_mono.xtime_nsec += tk->xtime_interval << shift;
    *clock_set |= accumulate_nsecs_to_secs(tk);

    /* Accumulate raw time */
    tk->tkr_raw.xtime_nsec += tk->raw_interval << shift;
    snsec_per_sec = (u64)NSEC_PER_SEC << tk->tkr_raw.shift;
    while (tk->tkr_raw.xtime_nsec >= snsec_per_sec) {
        tk->tkr_raw.xtime_nsec -= snsec_per_sec;
        tk->raw_sec++;
    }

    /* Accumulate error between NTP and clock interval */
    tk->ntp_error += tk->ntp_tick << shift;
    tk->ntp_error -= (tk->xtime_interval + tk->xtime_remainder) <<
        (tk->ntp_error_shift + shift);

    return offset;
}

/*
 * Apply a multiplier adjustment to the timekeeper
 */
static __always_inline
void timekeeping_apply_adjustment(struct timekeeper *tk,
                                  s64 offset,
                                  s32 mult_adj)
{
    s64 interval = tk->cycle_interval;

    if (mult_adj == 0) {
        return;
    } else if (mult_adj == -1) {
        interval = -interval;
        offset = -offset;
    } else if (mult_adj != 1) {
        interval *= mult_adj;
        offset *= mult_adj;
    }

    /*
     * So the following can be confusing.
     *
     * To keep things simple, lets assume mult_adj == 1 for now.
     *
     * When mult_adj != 1, remember that the interval and offset values
     * have been appropriately scaled so the math is the same.
     *
     * The basic idea here is that we're increasing the multiplier
     * by one, this causes the xtime_interval to be incremented by
     * one cycle_interval. This is because:
     *  xtime_interval = cycle_interval * mult
     * So if mult is being incremented by one:
     *  xtime_interval = cycle_interval * (mult + 1)
     * Its the same as:
     *  xtime_interval = (cycle_interval * mult) + cycle_interval
     * Which can be shortened to:
     *  xtime_interval += cycle_interval
     *
     * So offset stores the non-accumulated cycles. Thus the current
     * time (in shifted nanoseconds) is:
     *  now = (offset * adj) + xtime_nsec
     * Now, even though we're adjusting the clock frequency, we have
     * to keep time consistent. In other words, we can't jump back
     * in time, and we also want to avoid jumping forward in time.
     *
     * So given the same offset value, we need the time to be the same
     * both before and after the freq adjustment.
     *  now = (offset * adj_1) + xtime_nsec_1
     *  now = (offset * adj_2) + xtime_nsec_2
     * So:
     *  (offset * adj_1) + xtime_nsec_1 =
     *      (offset * adj_2) + xtime_nsec_2
     * And we know:
     *  adj_2 = adj_1 + 1
     * So:
     *  (offset * adj_1) + xtime_nsec_1 =
     *      (offset * (adj_1+1)) + xtime_nsec_2
     *  (offset * adj_1) + xtime_nsec_1 =
     *      (offset * adj_1) + offset + xtime_nsec_2
     * Canceling the sides:
     *  xtime_nsec_1 = offset + xtime_nsec_2
     * Which gives us:
     *  xtime_nsec_2 = xtime_nsec_1 - offset
     * Which simplifies to:
     *  xtime_nsec -= offset
     */
    if ((mult_adj > 0) && (tk->tkr_mono.mult + mult_adj < mult_adj)) {
        /* NTP adjustment caused clocksource mult overflow */
        WARN_ON_ONCE(1);
        return;
    }

    tk->tkr_mono.mult += mult_adj;
    tk->xtime_interval += interval;
    tk->tkr_mono.xtime_nsec -= offset;
}

/*
 * Adjust the timekeeper's multiplier to the correct frequency
 * and also to reduce the accumulated error value.
 */
static void timekeeping_adjust(struct timekeeper *tk, s64 offset)
{
    u32 mult;

    /*
     * Determine the multiplier from the current NTP tick length.
     * Avoid expensive division when the tick length doesn't change.
     */
    if (likely(tk->ntp_tick == ntp_tick_length())) {
        mult = tk->tkr_mono.mult - tk->ntp_err_mult;
    } else {
        tk->ntp_tick = ntp_tick_length();
        mult = div64_u64((tk->ntp_tick >> tk->ntp_error_shift) -
                         tk->xtime_remainder, tk->cycle_interval);
    }

    /*
     * If the clock is behind the NTP time, increase the multiplier by 1
     * to catch up with it. If it's ahead and there was a remainder in the
     * tick division, the clock will slow down. Otherwise it will stay
     * ahead until the tick length changes to a non-divisible value.
     */
    tk->ntp_err_mult = tk->ntp_error > 0 ? 1 : 0;
    mult += tk->ntp_err_mult;

    timekeeping_apply_adjustment(tk, offset, mult - tk->tkr_mono.mult);

    if (unlikely(tk->tkr_mono.clock->maxadj &&
        (abs(tk->tkr_mono.mult - tk->tkr_mono.clock->mult) >
         tk->tkr_mono.clock->maxadj))) {
        printk_once(KERN_WARNING
                    "Adjusting %s more than 11%% (%ld vs %ld)\n",
                    tk->tkr_mono.clock->name, (long)tk->tkr_mono.mult,
                    (long)tk->tkr_mono.clock->mult +
                    tk->tkr_mono.clock->maxadj);
    }

    /*
     * It may be possible that when we entered this function, xtime_nsec
     * was very small.  Further, if we're slightly speeding the clocksource
     * in the code above, its possible the required corrective factor to
     * xtime_nsec could cause it to underflow.
     *
     * Now, since we have already accumulated the second and the NTP
     * subsystem has been notified via second_overflow(), we need to skip
     * the next update.
     */
    if (unlikely((s64)tk->tkr_mono.xtime_nsec < 0)) {
        tk->tkr_mono.xtime_nsec += (u64)NSEC_PER_SEC <<
            tk->tkr_mono.shift;
        tk->xtime_sec--;
        tk->skip_second_overflow = 1;
    }
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
                               tk->tkr_mono.cycle_last,
                               tk->tkr_mono.mask);

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

    /* Adjust the multiplier to correct NTP error */
    timekeeping_adjust(tk, offset);

    /*
     * Finally, make sure that after the rounding
     * xtime_nsec isn't larger than NSEC_PER_SEC
     */
    clock_set |= accumulate_nsecs_to_secs(tk);

    write_seqcount_begin(&tk_core.seq);
    /*
     * Update the real timekeeper.
     *
     * We could avoid this memcpy by switching pointers, but that
     * requires changes to all other timekeeper usage sites as
     * well, i.e. move the timekeeper pointer getter into the
     * spinlocked/seqcount protected sections. And we trade this
     * memcpy under the tk_core.seq against one before we start
     * updating.
     */
    timekeeping_update(tk, clock_set);
    memcpy(real_tk, tk, sizeof(*tk));
    /* The memcpy must come last. Do not put anything here! */
    write_seqcount_end(&tk_core.seq);

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

/**
 * timekeeping_valid_for_hres - Check if timekeeping is suitable for hres
 */
int timekeeping_valid_for_hres(void)
{
    struct timekeeper *tk = &tk_core.timekeeper;
    unsigned int seq;
    int ret;

    do {
        seq = read_seqcount_begin(&tk_core.seq);

        ret = tk->tkr_mono.clock->flags & CLOCK_SOURCE_VALID_FOR_HRES;

    } while (read_seqcount_retry(&tk_core.seq, seq));

    return ret;
}

static inline void tk_normalize_xtime(struct timekeeper *tk)
{
    while (tk->tkr_mono.xtime_nsec >= ((u64)NSEC_PER_SEC << tk->tkr_mono.shift)) {
        tk->tkr_mono.xtime_nsec -= (u64)NSEC_PER_SEC << tk->tkr_mono.shift;
        tk->xtime_sec++;
    }
    while (tk->tkr_raw.xtime_nsec >= ((u64)NSEC_PER_SEC << tk->tkr_raw.shift)) {
        tk->tkr_raw.xtime_nsec -= (u64)NSEC_PER_SEC << tk->tkr_raw.shift;
        tk->raw_sec++;
    }
}

/**
 * timekeeping_forward_now - update clock to the current time
 * @tk:     Pointer to the timekeeper to update
 *
 * Forward the current clock to update its state since the last call to
 * update_wall_time(). This is useful before significant clock changes,
 * as it avoids having to deal with this time offset explicitly.
 */
static void timekeeping_forward_now(struct timekeeper *tk)
{
    u64 cycle_now, delta;

    cycle_now = tk_clock_read(&tk->tkr_mono);
    delta = clocksource_delta(cycle_now, tk->tkr_mono.cycle_last,
                              tk->tkr_mono.mask);
    tk->tkr_mono.cycle_last = cycle_now;
    tk->tkr_raw.cycle_last  = cycle_now;

    tk->tkr_mono.xtime_nsec += delta * tk->tkr_mono.mult;
    tk->tkr_raw.xtime_nsec += delta * tk->tkr_raw.mult;

    tk_normalize_xtime(tk);
}

/*
 * change_clocksource - Swaps clocksources if a new one is available
 *
 * Accumulates current time interval and initializes new clocksource
 */
static int change_clocksource(void *data)
{
    struct timekeeper *tk = &tk_core.timekeeper;
    struct clocksource *new, *old = NULL;
    unsigned long flags;
    bool change = false;

    new = (struct clocksource *) data;

    /*
     * If the cs is in module, get a module reference. Succeeds
     * for built-in code (owner == NULL) as well.
     */
    if (try_module_get(new->owner)) {
        if (!new->enable || new->enable(new) == 0)
            change = true;
        else
            module_put(new->owner);
    }

    raw_spin_lock_irqsave(&timekeeper_lock, flags);
    write_seqcount_begin(&tk_core.seq);

    timekeeping_forward_now(tk);

    if (change) {
        old = tk->tkr_mono.clock;
        tk_setup_internals(tk, new);
    }

    timekeeping_update(tk, TK_CLEAR_NTP | TK_MIRROR | TK_CLOCK_WAS_SET);

    write_seqcount_end(&tk_core.seq);
    raw_spin_unlock_irqrestore(&timekeeper_lock, flags);

    if (old) {
        if (old->disable)
            old->disable(old);

        module_put(old->owner);
    }

    return 0;
}

static inline struct timespec64 tk_xtime(const struct timekeeper *tk)
{
    struct timespec64 ts;

    ts.tv_sec = tk->xtime_sec;
    ts.tv_nsec = (long)(tk->tkr_mono.xtime_nsec >> tk->tkr_mono.shift);
    return ts;
}

/**
 * timekeeping_notify - Install a new clock source
 * @clock:      pointer to the clock source
 *
 * This function is called from clocksource.c after a new, better clock
 * source has been registered. The caller holds the clocksource_mutex.
 */
int timekeeping_notify(struct clocksource *clock)
{
    struct timekeeper *tk = &tk_core.timekeeper;

    if (tk->tkr_mono.clock == clock)
        return 0;
    stop_machine(change_clocksource, clock, NULL);
    tick_clock_notify();
    return tk->tkr_mono.clock == clock ? 0 : -1;
}

void ktime_get_coarse_real_ts64(struct timespec64 *ts)
{
    struct timekeeper *tk = &tk_core.timekeeper;
    unsigned int seq;

    do {
        seq = read_seqcount_begin(&tk_core.seq);

        *ts = tk_xtime(tk);
    } while (read_seqcount_retry(&tk_core.seq, seq));
}
EXPORT_SYMBOL(ktime_get_coarse_real_ts64);

/**
 * ktime_get_real_seconds - Get the seconds portion of CLOCK_REALTIME
 *
 * Returns the wall clock seconds since 1970.
 *
 * For 64bit systems the fast access to tk->xtime_sec is preserved. On
 * 32bit systems the access must be protected with the sequence
 * counter to provide "atomic" access to the 64bit tk->xtime_sec
 * value.
 */
time64_t ktime_get_real_seconds(void)
{
    struct timekeeper *tk = &tk_core.timekeeper;

    return tk->xtime_sec;
}
EXPORT_SYMBOL_GPL(ktime_get_real_seconds);

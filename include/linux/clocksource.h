/* SPDX-License-Identifier: GPL-2.0 */
/*  linux/include/linux/clocksource.h
 *
 *  This file contains the structure definitions for clocksources.
 *
 *  If you are not a clocksource, or timekeeping code, you should
 *  not be including this file!
 */
#ifndef _LINUX_CLOCKSOURCE_H
#define _LINUX_CLOCKSOURCE_H

#include <linux/types.h>
#include <linux/timex.h>
#include <linux/time.h>
#include <linux/list.h>
#include <linux/cache.h>
//#include <linux/timer.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/clocksource_ids.h>
#include <asm/div64.h>
#include <asm/io.h>

struct clocksource;
struct module;

#if 0
#include <asm/clocksource.h>
#endif
#include <vdso/clocksource.h>

/**
 * struct clocksource - hardware abstraction for a free running counter
 *  Provides mostly state-free accessors to the underlying hardware.
 *  This is the structure used for system time.
 *
 * @read:       Returns a cycle value, passes clocksource as argument
 * @mask:       Bitmask for two's complement
 *          subtraction of non 64 bit counters
 * @mult:       Cycle to nanosecond multiplier
 * @shift:      Cycle to nanosecond divisor (power of two)
 * @max_idle_ns:    Maximum idle time permitted by the clocksource (nsecs)
 * @maxadj:     Maximum adjustment value to mult (~11%)
 * @uncertainty_margin: Maximum uncertainty in nanoseconds per half second.
 *          Zero says to use default WATCHDOG_THRESHOLD.
 * @archdata:       Optional arch-specific data
 * @max_cycles:     Maximum safe cycle value which won't overflow on
 *          multiplication
 * @name:       Pointer to clocksource name
 * @list:       List head for registration (internal)
 * @rating:     Rating value for selection (higher is better)
 *          To avoid rating inflation the following
 *          list should give you a guide as to how
 *          to assign your clocksource a rating
 *          1-99: Unfit for real use
 *              Only available for bootup and testing purposes.
 *          100-199: Base level usability.
 *              Functional for real use, but not desired.
 *          200-299: Good.
 *              A correct and usable clocksource.
 *          300-399: Desired.
 *              A reasonably fast and accurate clocksource.
 *          400-499: Perfect
 *              The ideal clocksource. A must-use where
 *              available.
 * @id:         Defaults to CSID_GENERIC. The id value is captured
 *          in certain snapshot functions to allow callers to
 *          validate the clocksource from which the snapshot was
 *          taken.
 * @flags:      Flags describing special properties
 * @enable:     Optional function to enable the clocksource
 * @disable:        Optional function to disable the clocksource
 * @suspend:        Optional suspend function for the clocksource
 * @resume:     Optional resume function for the clocksource
 * @mark_unstable:  Optional function to inform the clocksource driver that
 *          the watchdog marked the clocksource unstable
 * @tick_stable:        Optional function called periodically from the watchdog
 *          code to provide stable synchronization points
 * @wd_list:        List head to enqueue into the watchdog list (internal)
 * @cs_last:        Last clocksource value for clocksource watchdog
 * @wd_last:        Last watchdog value corresponding to @cs_last
 * @owner:      Module reference, must be set by clocksource in modules
 *
 * Note: This struct is not used in hotpathes of the timekeeping code
 * because the timekeeper caches the hot path fields in its own data
 * structure, so no cache line alignment is required,
 *
 * The pointer to the clocksource itself is handed to the read
 * callback. If you need extra information there you can wrap struct
 * clocksource into your own struct. Depending on the amount of
 * information you need you should consider to cache line align that
 * structure.
 */
struct clocksource {
    u64         (*read)(struct clocksource *cs);
    u64         mask;
    u32         mult;
    u32         shift;
    u64         max_idle_ns;
    u32         maxadj;
    u32         uncertainty_margin;
    u64         max_cycles;
    const char  *name;
    struct list_head    list;
    int         rating;
    enum clocksource_ids    id;
    enum vdso_clock_mode    vdso_clock_mode;
    unsigned long       flags;

    int         (*enable)(struct clocksource *cs);
    void        (*disable)(struct clocksource *cs);
    void        (*suspend)(struct clocksource *cs);
    void        (*resume)(struct clocksource *cs);
    void        (*mark_unstable)(struct clocksource *cs);
    void        (*tick_stable)(struct clocksource *cs);

    /* private: */
    struct module   *owner;
};

extern void timer_probe(void);

#define TIMER_OF_DECLARE(name, compat, fn) \
    OF_DECLARE_1_RET(timer, name, compat, fn)

/*
 * Don't call __clocksource_register_scale directly, use
 * clocksource_register_hz/khz
 */
extern int
__clocksource_register_scale(struct clocksource *cs, u32 scale, u32 freq);
extern void
__clocksource_update_freq_scale(struct clocksource *cs, u32 scale, u32 freq);

/*
 * Don't call this unless you are a default clocksource
 * (AKA: jiffies) and absolutely have to.
 */
static inline int __clocksource_register(struct clocksource *cs)
{
    return __clocksource_register_scale(cs, 1, 0);
}

static inline int clocksource_register_hz(struct clocksource *cs, u32 hz)
{
    return __clocksource_register_scale(cs, 1, hz);
}

/*
 * Clock source flags bits::
 */
#define CLOCK_SOURCE_IS_CONTINUOUS      0x01
#define CLOCK_SOURCE_MUST_VERIFY        0x02

#define CLOCK_SOURCE_WATCHDOG           0x10
#define CLOCK_SOURCE_VALID_FOR_HRES     0x20
#define CLOCK_SOURCE_UNSTABLE           0x40
#define CLOCK_SOURCE_SUSPEND_NONSTOP    0x80
#define CLOCK_SOURCE_RESELECT           0x100
#define CLOCK_SOURCE_VERIFY_PERCPU      0x200
/* simplify initialization of mask field */
#define CLOCKSOURCE_MASK(bits) GENMASK_ULL((bits) - 1, 0)

extern void clocksource_arch_init(struct clocksource *cs);

/**
 * clocksource_cyc2ns - converts clocksource cycles to nanoseconds
 * @cycles: cycles
 * @mult:   cycle to nanosecond multiplier
 * @shift:  cycle to nanosecond divisor (power of two)
 *
 * Converts clocksource cycles to nanoseconds, using the given @mult and @shift.
 * The code is optimized for performance and is not intended to work
 * with absolute clocksource cycles (as those will easily overflow),
 * but is only intended to be used with relative (delta) clocksource cycles.
 *
 * XXX - This could use some mult_lxl_ll() asm optimization
 */
static inline s64 clocksource_cyc2ns(u64 cycles, u32 mult, u32 shift)
{
    return ((u64) cycles * mult) >> shift;
}

extern struct clocksource * __init clocksource_default_clock(void);

extern u64
clocks_calc_max_nsecs(u32 mult, u32 shift, u32 maxadj, u64 mask, u64 *max_cycles);
extern void
clocks_calc_mult_shift(u32 *mult, u32 *shift, u32 from, u32 to, u32 minsec);

extern int timekeeping_notify(struct clocksource *clock);

#endif /* _LINUX_CLOCKSOURCE_H */

// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/delay.h>
#include <linux/math.h>
#include <linux/param.h>
#include <linux/timex.h>
#include <linux/types.h>
#include <linux/export.h>

#include <asm/processor.h>

/*
 * This is copies from arch/arm/include/asm/delay.h
 *
 * Loop (or tick) based delay:
 *
 * loops = loops_per_jiffy * jiffies_per_sec * delay_us / us_per_sec
 *
 * where:
 *
 * jiffies_per_sec = HZ
 * us_per_sec = 1000000
 *
 * Therefore the constant part is HZ / 1000000 which is a small
 * fractional number. To make this usable with integer math, we
 * scale up this constant by 2^31, perform the actual multiplication,
 * and scale the result back down by 2^31 with a simple shift:
 *
 * loops = (loops_per_jiffy * delay_us * UDELAY_MULT) >> 31
 *
 * where:
 *
 * UDELAY_MULT = 2^31 * HZ / 1000000
 *             = (2^31 / 1000000) * HZ
 *             = 2147.483648 * HZ
 *             = 2147 * HZ + 483648 * HZ / 1000000
 *
 * 31 is the biggest scale shift value that won't overflow 32 bits for
 * delay_us * UDELAY_MULT assuming HZ <= 1000 and delay_us <= 2000.
 */
#define MAX_UDELAY_US   2000
#define MAX_UDELAY_HZ   1000
#define UDELAY_MULT (2147UL * HZ + 483648UL * HZ / 1000000UL)
#define UDELAY_SHIFT    31

#if HZ > MAX_UDELAY_HZ
#error "HZ > MAX_UDELAY_HZ"
#endif

void __delay(unsigned long cycles)
{
    u64 t0 = get_cycles();

    while ((unsigned long)(get_cycles() - t0) < cycles)
        cpu_relax();
}
EXPORT_SYMBOL(__delay);

void udelay(unsigned long usecs)
{
    u64 ucycles = (u64)usecs * lpj_fine * UDELAY_MULT;
    u64 n;

    if (unlikely(usecs > MAX_UDELAY_US)) {
        n = (u64)usecs * riscv_timebase;
        do_div(n, 1000000);

        __delay(n);
        return;
    }

    __delay(ucycles >> UDELAY_SHIFT);
}
EXPORT_SYMBOL(udelay);

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MATH64_H
#define _LINUX_MATH64_H

#include <linux/types.h>
#include <linux/math.h>
#if 0
#include <vdso/math64.h>
#endif
#include <asm/div64.h>

/*
 * div_s64_rem - signed 64bit divide with 32bit divisor with remainder
 * @dividend: signed 64bit dividend
 * @divisor: signed 32bit divisor
 * @remainder: pointer to signed 32bit remainder
 *
 * Return: sets ``*remainder``, then returns dividend / divisor
 */
static inline s64 div_s64_rem(s64 dividend, s32 divisor, s32 *remainder)
{
    *remainder = dividend % divisor;
    return dividend / divisor;
}

/**
 * div_u64_rem - unsigned 64bit divide with 32bit divisor with remainder
 * @dividend: unsigned 64bit dividend
 * @divisor: unsigned 32bit divisor
 * @remainder: pointer to unsigned 32bit remainder
 *
 * Return: sets ``*remainder``, then returns dividend / divisor
 *
 * This is commonly provided by 32bit archs to provide an optimized 64bit
 * divide.
 */
static inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
    *remainder = dividend % divisor;
    return dividend / divisor;
}

/**
 * div_u64 - unsigned 64bit divide with 32bit divisor
 * @dividend: unsigned 64bit dividend
 * @divisor: unsigned 32bit divisor
 *
 * This is the most common 64bit divide and should be used if possible,
 * as many 32bit archs can optimize this variant better than a full 64bit
 * divide.
 */
#ifndef div_u64
static inline u64 div_u64(u64 dividend, u32 divisor)
{
    u32 remainder;
    return div_u64_rem(dividend, divisor, &remainder);
}
#endif

/*
 * div64_u64 - unsigned 64bit divide with 64bit divisor
 * @dividend: unsigned 64bit dividend
 * @divisor: unsigned 64bit divisor
 *
 * Return: dividend / divisor
 */
static inline u64 div64_u64(u64 dividend, u64 divisor)
{
    return dividend / divisor;
}

#ifndef mul_u32_u32
/*
 * Many a GCC version messes this up and generates a 64x64 mult :-(
 */
static inline u64 mul_u32_u32(u32 a, u32 b)
{
    return (u64)a * b;
}
#endif

#ifndef mul_u64_u32_shr
static inline u64 mul_u64_u32_shr(u64 a, u32 mul, unsigned int shift)
{
    u32 ah, al;
    u64 ret;

    al = a;
    ah = a >> 32;

    ret = mul_u32_u32(al, mul) >> shift;
    if (ah)
        ret += mul_u32_u32(ah, mul) << (32 - shift);

    return ret;
}
#endif /* mul_u64_u32_shr */

#endif /* _LINUX_MATH64_H */

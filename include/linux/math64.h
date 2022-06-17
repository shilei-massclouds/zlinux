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

#endif /* _LINUX_MATH64_H */

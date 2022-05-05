/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MATH_H
#define _LINUX_MATH_H

#include <asm/div64.h>
#include <uapi/linux/kernel.h>

/**
 * roundup - round up to the next specified multiple
 * @x: the value to up
 * @y: multiple to round up to
 *
 * Rounds @x up to next multiple of @y. If @y will always be a power
 * of 2, consider using the faster round_up().
 */
#define roundup(x, y) ({                \
    typeof(y) __y = y;                  \
    (((x) + (__y - 1)) / __y) * __y;    \
})

/**
 * rounddown - round down to next specified multiple
 * @x: the value to round
 * @y: multiple to round down to
 *
 * Rounds @x down to next multiple of @y. If @y will always be a power
 * of 2, consider using the faster round_down().
 */
#define rounddown(x, y) ({  \
    typeof(x) __x = (x);    \
    __x - (__x % (y));      \
})

#endif  /* _LINUX_MATH_H */

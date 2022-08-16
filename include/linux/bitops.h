/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BITOPS_H
#define _LINUX_BITOPS_H

#include <asm/types.h>
#include <linux/bits.h>
#include <linux/math.h>

#include <uapi/linux/kernel.h>

#define aligned_byte_mask(n) ((1UL << 8*(n))-1)

#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)   DIV_ROUND_UP(nr, BITS_PER_TYPE(long))

extern unsigned int __sw_hweight8(unsigned int w);
extern unsigned int __sw_hweight16(unsigned int w);
extern unsigned int __sw_hweight32(unsigned int w);
extern unsigned long __sw_hweight64(__u64 w);

/* Include this here because some architectures need generic_ffs/fls
 * in scope.
 */
#include <asm/bitops.h>

#ifdef __KERNEL__

/**
 * rol64 - rotate a 64-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u64 rol64(__u64 word, unsigned int shift)
{
    return (word << (shift & 63)) | (word >> ((-shift) & 63));
}

static inline unsigned fls_long(unsigned long l)
{
    if (sizeof(l) == 4)
        return fls(l);
    return fls64(l);
}

static __always_inline unsigned long hweight_long(unsigned long w)
{
    return sizeof(w) == 4 ? hweight32(w) : hweight64((__u64)w);
}

/**
 * get_count_order_long - get order after rounding @l up to power of 2
 * @l: parameter
 *
 * it is same as get_count_order() but with long type parameter
 */
static inline int get_count_order_long(unsigned long l)
{
    if (l == 0UL)
        return -1;
    return (int)fls_long(--l);
}

#endif /* __KERNEL__ */
#endif

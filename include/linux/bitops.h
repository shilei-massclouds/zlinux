/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BITOPS_H
#define _LINUX_BITOPS_H

#include <asm/types.h>
#include <linux/bits.h>

/* Include this here because some architectures need generic_ffs/fls
 * in scope.
 */
#include <asm/bitops.h>

#ifdef __KERNEL__

#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)   DIV_ROUND_UP(nr, BITS_PER_TYPE(long))

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

#endif /* __KERNEL__ */
#endif

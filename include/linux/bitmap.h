/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_BITMAP_H
#define __LINUX_BITMAP_H

#ifndef __ASSEMBLY__

//#include <linux/align.h>
#include <linux/bitops.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/types.h>

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

int __bitmap_weight(const unsigned long *bitmap, unsigned int nbits);

static __always_inline int
bitmap_weight(const unsigned long *src, unsigned int nbits)
{
    if (small_const_nbits(nbits))
        return hweight_long(*src & BITMAP_LAST_WORD_MASK(nbits));
    return __bitmap_weight(src, nbits);
}

#endif /* __ASSEMBLY__ */

#endif /* __LINUX_BITMAP_H */

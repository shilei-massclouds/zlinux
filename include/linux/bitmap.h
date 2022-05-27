/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_BITMAP_H
#define __LINUX_BITMAP_H

#ifndef __ASSEMBLY__

#include <linux/align.h>
#include <linux/bitops.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/types.h>

#define BITMAP_MEM_ALIGNMENT 8
#define BITMAP_MEM_MASK (BITMAP_MEM_ALIGNMENT - 1)

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

static inline void bitmap_zero(unsigned long *dst, unsigned int nbits)
{
    unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
    memset(dst, 0, len);
}

int __bitmap_weight(const unsigned long *bitmap, unsigned int nbits);

static __always_inline int
bitmap_weight(const unsigned long *src, unsigned int nbits)
{
    if (small_const_nbits(nbits))
        return hweight_long(*src & BITMAP_LAST_WORD_MASK(nbits));
    return __bitmap_weight(src, nbits);
}

static inline void
bitmap_copy(unsigned long *dst, const unsigned long *src, unsigned int nbits)
{
    unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
    memcpy(dst, src, len);
}

static inline bool bitmap_empty(const unsigned long *src, unsigned nbits)
{
    if (small_const_nbits(nbits))
        return ! (*src & BITMAP_LAST_WORD_MASK(nbits));

    return find_first_bit(src, nbits) == nbits;
}

static inline void bitmap_fill(unsigned long *dst, unsigned int nbits)
{
    unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
    memset(dst, 0xff, len);
}

void __bitmap_set(unsigned long *map, unsigned int start, int len);

static __always_inline void bitmap_set(unsigned long *map, unsigned int start,
        unsigned int nbits)
{
    if (__builtin_constant_p(nbits) && nbits == 1)
        __set_bit(start, map);
    else if (__builtin_constant_p(start & BITMAP_MEM_MASK) &&
             IS_ALIGNED(start, BITMAP_MEM_ALIGNMENT) &&
             __builtin_constant_p(nbits & BITMAP_MEM_MASK) &&
             IS_ALIGNED(nbits, BITMAP_MEM_ALIGNMENT))
        memset((char *)map + start / 8, 0xff, nbits / 8);
    else
        __bitmap_set(map, start, nbits);
}

#endif /* __ASSEMBLY__ */

#endif /* __LINUX_BITMAP_H */

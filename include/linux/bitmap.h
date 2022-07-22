/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_BITMAP_H
#define __LINUX_BITMAP_H

#ifndef __ASSEMBLY__

#include <linux/align.h>
#include <linux/bitops.h>
#include <linux/find.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/types.h>

#define BITMAP_MEM_ALIGNMENT 8
#define BITMAP_MEM_MASK (BITMAP_MEM_ALIGNMENT - 1)

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (BITS_PER_LONG - 1)))

void __bitmap_clear(unsigned long *map, unsigned int start, int len);

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

static inline void
bitmap_next_clear_region(unsigned long *bitmap,
                         unsigned int *rs, unsigned int *re,
                         unsigned int end)
{
    *rs = find_next_zero_bit(bitmap, end, *rs);
    *re = find_next_bit(bitmap, end, *rs + 1);
}

static inline void
bitmap_next_set_region(unsigned long *bitmap,
                       unsigned int *rs, unsigned int *re,
                       unsigned int end)
{
    *rs = find_next_bit(bitmap, end, *rs);
    *re = find_next_zero_bit(bitmap, end, *rs + 1);
}

static __always_inline void
bitmap_clear(unsigned long *map, unsigned int start, unsigned int nbits)
{
    if (__builtin_constant_p(nbits) && nbits == 1)
        __clear_bit(start, map);
    else if (__builtin_constant_p(start & BITMAP_MEM_MASK) &&
             IS_ALIGNED(start, BITMAP_MEM_ALIGNMENT) &&
             __builtin_constant_p(nbits & BITMAP_MEM_MASK) &&
             IS_ALIGNED(nbits, BITMAP_MEM_ALIGNMENT))
        memset((char *)map + start / 8, 0, nbits / 8);
    else
        __bitmap_clear(map, start, nbits);
}

/*
 * Bitmap region iterators.  Iterates over the bitmap between [@start, @end).
 * @rs and @re should be integer variables and will be set to start and end
 * index of the current clear or set region.
 */
#define bitmap_for_each_clear_region(bitmap, rs, re, start, end)         \
    for ((rs) = (start),                             \
         bitmap_next_clear_region((bitmap), &(rs), &(re), (end));        \
         (rs) < (re);                            \
         (rs) = (re) + 1,                            \
         bitmap_next_clear_region((bitmap), &(rs), &(re), (end)))

#define bitmap_for_each_set_region(bitmap, rs, re, start, end)           \
    for ((rs) = (start),                             \
         bitmap_next_set_region((bitmap), &(rs), &(re), (end));      \
         (rs) < (re);                            \
         (rs) = (re) + 1,                            \
         bitmap_next_set_region((bitmap), &(rs), &(re), (end)))

unsigned long
bitmap_find_next_zero_area_off(unsigned long *map, unsigned long size,
                               unsigned long start, unsigned int nr,
                               unsigned long align_mask,
                               unsigned long align_offset);

/**
 * bitmap_find_next_zero_area - find a contiguous aligned zero area
 * @map: The address to base the search on
 * @size: The bitmap size in bits
 * @start: The bitnumber to start searching at
 * @nr: The number of zeroed bits we're looking for
 * @align_mask: Alignment mask for zero area
 *
 * The @align_mask should be one less than a power of 2; the effect is that
 * the bit offset of all zero areas this function finds is multiples of that
 * power of 2. A @align_mask of 0 means no alignment is required.
 */
static inline unsigned long
bitmap_find_next_zero_area(unsigned long *map, unsigned long size,
                           unsigned long start, unsigned int nr,
                           unsigned long align_mask)
{
    return bitmap_find_next_zero_area_off(map, size, start, nr, align_mask, 0);
}

int __bitmap_and(unsigned long *dst, const unsigned long *bitmap1,
                 const unsigned long *bitmap2, unsigned int nbits);
void __bitmap_or(unsigned long *dst, const unsigned long *bitmap1,
                 const unsigned long *bitmap2, unsigned int nbits);

static inline int
bitmap_and(unsigned long *dst, const unsigned long *src1,
           const unsigned long *src2, unsigned int nbits)
{
    if (small_const_nbits(nbits))
        return (*dst = *src1 & *src2 & BITMAP_LAST_WORD_MASK(nbits)) != 0;
    return __bitmap_and(dst, src1, src2, nbits);
}

static inline void
bitmap_or(unsigned long *dst, const unsigned long *src1,
          const unsigned long *src2, unsigned int nbits)
{
    if (small_const_nbits(nbits))
        *dst = *src1 | *src2;
    else
        __bitmap_or(dst, src1, src2, nbits);
}

int __bitmap_intersects(const unsigned long *bitmap1,
                        const unsigned long *bitmap2,
                        unsigned int nbits);

static inline int bitmap_intersects(const unsigned long *src1,
                                    const unsigned long *src2,
                                    unsigned int nbits)
{
    if (small_const_nbits(nbits))
        return ((*src1 & *src2) & BITMAP_LAST_WORD_MASK(nbits)) != 0;
    else
        return __bitmap_intersects(src1, src2, nbits);
}

void __bitmap_complement(unsigned long *dst, const unsigned long *src,
                         unsigned int nbits);

static inline void
bitmap_complement(unsigned long *dst, const unsigned long *src,
                  unsigned int nbits)
{
    if (small_const_nbits(nbits))
        *dst = ~(*src);
    else
        __bitmap_complement(dst, src, nbits);
}

#endif /* __ASSEMBLY__ */

#endif /* __LINUX_BITMAP_H */

// SPDX-License-Identifier: GPL-2.0-only
/*
 * lib/bitmap.c
 * Helper functions for bitmap.h.
 */

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/ctype.h>
//#include <linux/device.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/thread_info.h>
#include <linux/uaccess.h>

#include <asm/page.h>

//#include "kstrtox.h"

int __bitmap_weight(const unsigned long *bitmap, unsigned int bits)
{
    unsigned int k, lim = bits/BITS_PER_LONG;
    int w = 0;

    for (k = 0; k < lim; k++)
        w += hweight_long(bitmap[k]);

    if (bits % BITS_PER_LONG)
        w += hweight_long(bitmap[k] & BITMAP_LAST_WORD_MASK(bits));

    return w;
}
EXPORT_SYMBOL(__bitmap_weight);

void __bitmap_set(unsigned long *map, unsigned int start, int len)
{
    unsigned long *p = map + BIT_WORD(start);
    const unsigned int size = start + len;
    int bits_to_set = BITS_PER_LONG - (start % BITS_PER_LONG);
    unsigned long mask_to_set = BITMAP_FIRST_WORD_MASK(start);

    while (len - bits_to_set >= 0) {
        *p |= mask_to_set;
        len -= bits_to_set;
        bits_to_set = BITS_PER_LONG;
        mask_to_set = ~0UL;
        p++;
    }
    if (len) {
        mask_to_set &= BITMAP_LAST_WORD_MASK(size);
        *p |= mask_to_set;
    }
}
EXPORT_SYMBOL(__bitmap_set);

void __bitmap_clear(unsigned long *map, unsigned int start, int len)
{
    unsigned long *p = map + BIT_WORD(start);
    const unsigned int size = start + len;
    int bits_to_clear = BITS_PER_LONG - (start % BITS_PER_LONG);
    unsigned long mask_to_clear = BITMAP_FIRST_WORD_MASK(start);

    while (len - bits_to_clear >= 0) {
        *p &= ~mask_to_clear;
        len -= bits_to_clear;
        bits_to_clear = BITS_PER_LONG;
        mask_to_clear = ~0UL;
        p++;
    }
    if (len) {
        mask_to_clear &= BITMAP_LAST_WORD_MASK(size);
        *p &= ~mask_to_clear;
    }
}
EXPORT_SYMBOL(__bitmap_clear);

/**
 * bitmap_find_next_zero_area_off - find a contiguous aligned zero area
 * @map: The address to base the search on
 * @size: The bitmap size in bits
 * @start: The bitnumber to start searching at
 * @nr: The number of zeroed bits we're looking for
 * @align_mask: Alignment mask for zero area
 * @align_offset: Alignment offset for zero area.
 *
 * The @align_mask should be one less than a power of 2; the effect is that
 * the bit offset of all zero areas this function finds plus @align_offset
 * is multiple of that power of 2.
 */
unsigned long
bitmap_find_next_zero_area_off(unsigned long *map, unsigned long size,
                               unsigned long start, unsigned int nr,
                               unsigned long align_mask,
                               unsigned long align_offset)
{
    unsigned long index, end, i;
again:
    index = find_next_zero_bit(map, size, start);

    /* Align allocation */
    index = __ALIGN_MASK(index + align_offset, align_mask) - align_offset;

    end = index + nr;
    if (end > size)
        return end;
    i = find_next_bit(map, end, index);
    if (i < end) {
        start = i + 1;
        goto again;
    }
    return index;
}
EXPORT_SYMBOL(bitmap_find_next_zero_area_off);

int __bitmap_and(unsigned long *dst, const unsigned long *bitmap1,
                 const unsigned long *bitmap2, unsigned int bits)
{
    unsigned int k;
    unsigned int lim = bits/BITS_PER_LONG;
    unsigned long result = 0;

    for (k = 0; k < lim; k++)
        result |= (dst[k] = bitmap1[k] & bitmap2[k]);
    if (bits % BITS_PER_LONG)
        result |= (dst[k] = bitmap1[k] & bitmap2[k] &
                   BITMAP_LAST_WORD_MASK(bits));
    return result != 0;
}
EXPORT_SYMBOL(__bitmap_and);

void __bitmap_or(unsigned long *dst, const unsigned long *bitmap1,
                 const unsigned long *bitmap2, unsigned int bits)
{
    unsigned int k;
    unsigned int nr = BITS_TO_LONGS(bits);

    for (k = 0; k < nr; k++)
        dst[k] = bitmap1[k] | bitmap2[k];
}
EXPORT_SYMBOL(__bitmap_or);

int __bitmap_intersects(const unsigned long *bitmap1,
                        const unsigned long *bitmap2,
                        unsigned int bits)
{
    unsigned int k, lim = bits/BITS_PER_LONG;
    for (k = 0; k < lim; ++k)
        if (bitmap1[k] & bitmap2[k])
            return 1;

    if (bits % BITS_PER_LONG)
        if ((bitmap1[k] & bitmap2[k]) & BITMAP_LAST_WORD_MASK(bits))
            return 1;
    return 0;
}
EXPORT_SYMBOL(__bitmap_intersects);

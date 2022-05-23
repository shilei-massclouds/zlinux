// SPDX-License-Identifier: GPL-2.0-or-later
/* bit search implementation
 *
 * Copyright (C) 2004 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * Copyright (C) 2008 IBM Corporation
 * 'find_last_bit' is written by Rusty Russell <rusty@rustcorp.com.au>
 * (Inspired by David Howell's find_next_bit implementation)
 *
 * Rewritten by Yury Norov <yury.norov@gmail.com> to decrease
 * size and improve performance, 2015.
 */

#include <linux/bitops.h>
#include <linux/bitmap.h>
#include <linux/export.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/swab.h>

#if !defined(find_next_bit) || !defined(find_next_zero_bit) ||          \
    !defined(find_next_bit_le) || !defined(find_next_zero_bit_le) ||    \
    !defined(find_next_and_bit)

/*
 * This is a common helper function for find_next_bit, find_next_zero_bit, and
 * find_next_and_bit. The differences are:
 *  - The "invert" argument, which is XORed with each fetched word before
 *    searching it for one bits.
 *  - The optional "addr2", which is anded with "addr1" if present.
 */
unsigned long
_find_next_bit(const unsigned long *addr1, const unsigned long *addr2,
               unsigned long nbits, unsigned long start,
               unsigned long invert, unsigned long le)
{
    unsigned long tmp, mask;

    if (unlikely(start >= nbits))
        return nbits;

    tmp = addr1[start / BITS_PER_LONG];
    if (addr2)
        tmp &= addr2[start / BITS_PER_LONG];
    tmp ^= invert;

    /* Handle 1st word. */
    mask = BITMAP_FIRST_WORD_MASK(start);
    if (le)
        mask = swab(mask);

    tmp &= mask;

    start = round_down(start, BITS_PER_LONG);

    while (!tmp) {
        start += BITS_PER_LONG;
        if (start >= nbits)
            return nbits;

        tmp = addr1[start / BITS_PER_LONG];
        if (addr2)
            tmp &= addr2[start / BITS_PER_LONG];
        tmp ^= invert;
    }

    if (le)
        tmp = swab(tmp);

    return min(start + __ffs(tmp), nbits);
}
EXPORT_SYMBOL(_find_next_bit);
#endif

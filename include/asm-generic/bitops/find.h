/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_GENERIC_BITOPS_FIND_H_
#define _ASM_GENERIC_BITOPS_FIND_H_

extern unsigned long
_find_next_bit(const unsigned long *addr1, const unsigned long *addr2,
               unsigned long nbits, unsigned long start,
               unsigned long invert, unsigned long le);

#ifndef find_next_bit
/**
 * find_next_bit - find the next set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The bitmap size in bits
 *
 * Returns the bit number for the next set bit
 * If no bits are set, returns @size.
 */
static inline
unsigned long find_next_bit(const unsigned long *addr,
                            unsigned long size,
                            unsigned long offset)
{
    if (small_const_nbits(size)) {
        unsigned long val;

        if (unlikely(offset >= size))
            return size;

        val = *addr & GENMASK(size - 1, offset);
        return val ? __ffs(val) : size;
    }

    return _find_next_bit(addr, NULL, size, offset, 0UL, 0);
}
#endif

#endif /*_ASM_GENERIC_BITOPS_FIND_H_ */

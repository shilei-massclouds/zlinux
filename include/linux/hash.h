#ifndef _LINUX_HASH_H
#define _LINUX_HASH_H
/* Fast hashing routine for ints,  longs and pointers.
   (C) 2002 Nadia Yvette Chambers, IBM */

#include <asm/types.h>
#include <linux/compiler.h>

/*
 * The "GOLDEN_RATIO_PRIME" is used in ifs/btrfs/brtfs_inode.h and
 * fs/inode.c.  It's not actually prime any more (the previous primes
 * were actively bad for hashing), but the name remains.
 */
#define hash_long(val, bits) hash_64(val, bits)
#define GOLDEN_RATIO_PRIME GOLDEN_RATIO_64

/*
 * This hash multiplies the input by a large odd number and takes the
 * high bits.  Since multiplication propagates changes to the most
 * significant end only, it is essential that the high bits of the
 * product be used for the hash value.
 *
 * Chuck Lever verified the effectiveness of this technique:
 * http://www.citi.umich.edu/techreports/reports/citi-tr-00-1.pdf
 *
 * Although a random odd number will do, it turns out that the golden
 * ratio phi = (sqrt(5)-1)/2, or its negative, has particularly nice
 * properties.  (See Knuth vol 3, section 6.4, exercise 9.)
 *
 * These are the negative, (1 - phi) = phi**2 = (3 - sqrt(5))/2,
 * which is very slightly easier to multiply by and makes no
 * difference to the hash distribution.
 */
#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

/*
 * The _generic versions exist only so lib/test_hash.c can compare
 * the arch-optimized versions with the generic.
 *
 * Note that if you change these, any <asm/hash.h> that aren't updated
 * to match need to have their HAVE_ARCH_* define values updated so the
 * self-test will not false-positive.
 */
#ifndef HAVE_ARCH__HASH_32
#define __hash_32 __hash_32_generic
#endif
static inline u32 __hash_32_generic(u32 val)
{
    return val * GOLDEN_RATIO_32;
}

static inline u32 hash_32(u32 val, unsigned int bits)
{
    /* High bits are more random, so use them. */
    return __hash_32(val) >> (32 - bits);
}

#define hash_64 hash_64_generic
static __always_inline u32 hash_64_generic(u64 val, unsigned int bits)
{
    /* 64x64-bit multiply is efficient on all 64-bit processors */
    return val * GOLDEN_RATIO_64 >> (64 - bits);
}

static inline u32 hash_ptr(const void *ptr, unsigned int bits)
{
    return hash_long((unsigned long)ptr, bits);
}

#endif /* _LINUX_HASH_H */

/* Copyright (C) 2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This file is provided under a dual BSD/GPLv2 license.
 *
 * SipHash: a fast short-input PRF
 * https://131002.net/siphash/
 *
 * This implementation is specifically for SipHash2-4 for a secure PRF
 * and HalfSipHash1-3/SipHash1-3 for an insecure PRF only suitable for
 * hashtables.
 */

#ifndef _LINUX_SIPHASH_H
#define _LINUX_SIPHASH_H

#include <linux/types.h>
#include <linux/kernel.h>

#define SIPHASH_ALIGNMENT __alignof__(u64)
typedef struct {
    u64 key[2];
} siphash_key_t;

u64 siphash_1u64(const u64 a, const siphash_key_t *key);

/*
 * These macros expose the raw SipHash and HalfSipHash permutations.
 * Do not use them directly! If you think you have a use for them,
 * be sure to CC the maintainer of this file explaining why.
 */

#define SIPHASH_PERMUTATION(a, b, c, d) ( \
    (a) += (b), (b) = rol64((b), 13), (b) ^= (a), (a) = rol64((a), 32), \
    (c) += (d), (d) = rol64((d), 16), (d) ^= (c), \
    (a) += (d), (d) = rol64((d), 21), (d) ^= (a), \
    (c) += (b), (b) = rol64((b), 17), (b) ^= (c), (c) = rol64((c), 32))

#endif /* _LINUX_SIPHASH_H */

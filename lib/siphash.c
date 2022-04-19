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

#include <linux/siphash.h>
//#include <asm/unaligned.h>

#define SIPROUND \
    do { \
    v0 += v1; v1 = rol64(v1, 13); v1 ^= v0; v0 = rol64(v0, 32); \
    v2 += v3; v3 = rol64(v3, 16); v3 ^= v2; \
    v0 += v3; v3 = rol64(v3, 21); v3 ^= v0; \
    v2 += v1; v1 = rol64(v1, 17); v1 ^= v2; v2 = rol64(v2, 32); \
    } while (0)

#define PREAMBLE(len) \
    u64 v0 = 0x736f6d6570736575ULL; \
    u64 v1 = 0x646f72616e646f6dULL; \
    u64 v2 = 0x6c7967656e657261ULL; \
    u64 v3 = 0x7465646279746573ULL; \
    u64 b = ((u64)(len)) << 56; \
    v3 ^= key->key[1]; \
    v2 ^= key->key[0]; \
    v1 ^= key->key[1]; \
    v0 ^= key->key[0];

#define POSTAMBLE \
    v3 ^= b; \
    SIPROUND; \
    SIPROUND; \
    v0 ^= b; \
    v2 ^= 0xff; \
    SIPROUND; \
    SIPROUND; \
    SIPROUND; \
    SIPROUND; \
    return (v0 ^ v1) ^ (v2 ^ v3);

/**
 * siphash_1u64 - compute 64-bit siphash PRF value of a u64
 * @first: first u64
 * @key: the siphash key
 */
u64 siphash_1u64(const u64 first, const siphash_key_t *key)
{
    PREAMBLE(8)
    v3 ^= first;
    SIPROUND;
    SIPROUND;
    v0 ^= first;
    POSTAMBLE
}
EXPORT_SYMBOL(siphash_1u64);

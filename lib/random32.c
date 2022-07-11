// SPDX-License-Identifier: GPL-2.0
/*
 * This is a maximally equidistributed combined Tausworthe generator
 * based on code from GNU Scientific Library 1.5 (30 Jun 2004)
 *
 * lfsr113 version:
 *
 * x_n = (s1_n ^ s2_n ^ s3_n ^ s4_n)
 *
 * s1_{n+1} = (((s1_n & 4294967294) << 18) ^ (((s1_n <<  6) ^ s1_n) >> 13))
 * s2_{n+1} = (((s2_n & 4294967288) <<  2) ^ (((s2_n <<  2) ^ s2_n) >> 27))
 * s3_{n+1} = (((s3_n & 4294967280) <<  7) ^ (((s3_n << 13) ^ s3_n) >> 21))
 * s4_{n+1} = (((s4_n & 4294967168) << 13) ^ (((s4_n <<  3) ^ s4_n) >> 12))
 *
 * The period of this generator is about 2^113 (see erratum paper).
 *
 * From: P. L'Ecuyer, "Maximally Equidistributed Combined Tausworthe
 * Generators", Mathematics of Computation, 65, 213 (1996), 203--213:
 * http://www.iro.umontreal.ca/~lecuyer/myftp/papers/tausme.ps
 * ftp://ftp.iro.umontreal.ca/pub/simulation/lecuyer/papers/tausme.ps
 *
 * There is an erratum in the paper "Tables of Maximally Equidistributed
 * Combined LFSR Generators", Mathematics of Computation, 68, 225 (1999),
 * 261--269: http://www.iro.umontreal.ca/~lecuyer/myftp/papers/tausme2.ps
 *
 *      ... the k_j most significant bits of z_j must be non-zero,
 *      for each j. (Note: this restriction also applies to the
 *      computer code given in [4], but was mistakenly not mentioned
 *      in that paper.)
 *
 * This affects the seeding procedure by imposing the requirement
 * s1 > 1, s2 > 7, s3 > 15, s4 > 127.
 */

#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/export.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#if 0
#include <asm/unaligned.h>
#endif

/*
 * The prandom_u32() implementation is now completely separate from the
 * prandom_state() functions, which are retained (for now) for compatibility.
 *
 * Because of (ab)use in the networking code for choosing random TCP/UDP port
 * numbers, which open DoS possibilities if guessable, we want something
 * stronger than a standard PRNG.  But the performance requirements of
 * the network code do not allow robust crypto for this application.
 *
 * So this is a homebrew Junior Spaceman implementation, based on the
 * lowest-latency trustworthy crypto primitive available, SipHash.
 * (The authors of SipHash have not been consulted about this abuse of
 * their work.)
 *
 * Standard SipHash-2-4 uses 2n+4 rounds to hash n words of input to
 * one word of output.  This abbreviated version uses 2 rounds per word
 * of output.
 */

struct siprand_state {
    unsigned long v0;
    unsigned long v1;
    unsigned long v2;
    unsigned long v3;
};

static DEFINE_PER_CPU(struct siprand_state, net_rand_state) __latent_entropy;
DEFINE_PER_CPU(unsigned long, net_rand_noise);
EXPORT_PER_CPU_SYMBOL(net_rand_noise);

/*
 * This is the core CPRNG function.  As "pseudorandom", this is not used
 * for truly valuable things, just intended to be a PITA to guess.
 * For maximum speed, we do just two SipHash rounds per word.  This is
 * the same rate as 4 rounds per 64 bits that SipHash normally uses,
 * so hopefully it's reasonably secure.
 *
 * There are two changes from the official SipHash finalization:
 * - We omit some constants XORed with v2 in the SipHash spec as irrelevant;
 *   they are there only to make the output rounds distinct from the input
 *   rounds, and this application has no input rounds.
 * - Rather than returning v0^v1^v2^v3, return v1+v3.
 *   If you look at the SipHash round, the last operation on v3 is
 *   "v3 ^= v0", so "v0 ^ v3" just undoes that, a waste of time.
 *   Likewise "v1 ^= v2".  (The rotate of v2 makes a difference, but
 *   it still cancels out half of the bits in v2 for no benefit.)
 *   Second, since the last combining operation was xor, continue the
 *   pattern of alternating xor/add for a tiny bit of extra non-linearity.
 */
static inline u32 siprand_u32(struct siprand_state *s)
{
    unsigned long v0 = s->v0, v1 = s->v1, v2 = s->v2, v3 = s->v3;
    unsigned long n = raw_cpu_read(net_rand_noise);

    v3 ^= n;
    PRND_SIPROUND(v0, v1, v2, v3);
    PRND_SIPROUND(v0, v1, v2, v3);
    v0 ^= n;
    s->v0 = v0;  s->v1 = v1;  s->v2 = v2;  s->v3 = v3;
    return v1 + v3;
}

/**
 *  prandom_u32 - pseudo random number generator
 *
 *  A 32 bit pseudo-random number is generated using a fast
 *  algorithm suitable for simulation. This algorithm is NOT
 *  considered safe for cryptographic use.
 */
u32 prandom_u32(void)
{
    struct siprand_state *state = get_cpu_ptr(&net_rand_state);
    u32 res = siprand_u32(state);

    put_cpu_ptr(&net_rand_state);
    return res;
}
EXPORT_SYMBOL(prandom_u32);

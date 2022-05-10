/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SWAB_H
#define _UAPI_LINUX_SWAB_H

#include <linux/types.h>
#include <linux/compiler.h>
#include <asm/bitsperlong.h>

#define ___constant_swab32(x) ((__u32)(             \
    (((__u32)(x) & (__u32)0x000000ffUL) << 24) |    \
    (((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |    \
    (((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |    \
    (((__u32)(x) & (__u32)0xff000000UL) >> 24)))

#define ___constant_swab64(x) ((__u64)(             \
    (((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) |   \
    (((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40) |   \
    (((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) |   \
    (((__u64)(x) & (__u64)0x00000000ff000000ULL) <<  8) |   \
    (((__u64)(x) & (__u64)0x000000ff00000000ULL) >>  8) |   \
    (((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) |   \
    (((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40) |   \
    (((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56)))

static inline __attribute_const__ __u32 __fswab32(__u32 val)
{
    return ___constant_swab32(val);
}

static inline __attribute_const__ __u64 __fswab64(__u64 val)
{
    return ___constant_swab64(val);
}

#define __swab32(x) \
    (__builtin_constant_p((__u32)(x)) ? \
    ___constant_swab32(x) :             \
    __fswab32(x))

/**
 * __swab64 - return a byteswapped 64-bit value
 * @x: value to byteswap
 */
#define __swab64(x)                     \
    (__builtin_constant_p((__u64)(x)) ? \
    ___constant_swab64(x) :             \
    __fswab64(x))

/**
 * __swab32p - return a byteswapped 32-bit value from a pointer
 * @p: pointer to a naturally-aligned 32-bit value
 */
static __always_inline __u32 __swab32p(const __u32 *p)
{
    return __swab32(*p);
}

static __always_inline unsigned long __swab(const unsigned long y)
{
    return __swab64(y);
}

#endif /* _UAPI_LINUX_SWAB_H */

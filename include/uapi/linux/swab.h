/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_SWAB_H
#define _UAPI_LINUX_SWAB_H

#include <linux/types.h>
#include <linux/compiler.h>
#include <asm/bitsperlong.h>

/*
 * casts are necessary for constants, because we never know how for sure
 * how U/UL/ULL map to __u16, __u32, __u64. At least not in a portable way.
 */
#define ___constant_swab16(x) ((__u16)(             \
    (((__u16)(x) & (__u16)0x00ffU) << 8) |          \
    (((__u16)(x) & (__u16)0xff00U) >> 8)))

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

static inline __attribute_const__ __u16 __fswab16(__u16 val)
{
    return ___constant_swab16(val);
}

static inline __attribute_const__ __u32 __fswab32(__u32 val)
{
    return ___constant_swab32(val);
}

static inline __attribute_const__ __u64 __fswab64(__u64 val)
{
    return ___constant_swab64(val);
}

/**
 * __swab16 - return a byteswapped 16-bit value
 * @x: value to byteswap
 */
#define __swab16(x) \
    (__builtin_constant_p((__u16)(x)) ? \
    ___constant_swab16(x) :             \
    __fswab16(x))

/**
 * __swab32 - return a byteswapped 32-bit value
 * @x: value to byteswap
 */
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

/**
 * __swab16p - return a byteswapped 16-bit value from a pointer
 * @p: pointer to a naturally-aligned 16-bit value
 */
static __always_inline __u16 __swab16p(const __u16 *p)
{
    return __swab16(*p);
}

#endif /* _UAPI_LINUX_SWAB_H */

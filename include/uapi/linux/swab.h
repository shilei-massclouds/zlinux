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

static inline __attribute_const__ __u32 __fswab32(__u32 val)
{
    return ___constant_swab32(val);
}

#define __swab32(x) \
    (__builtin_constant_p((__u32)(x)) ? \
    ___constant_swab32(x) :             \
    __fswab32(x))

/**
 * __swab32p - return a byteswapped 32-bit value from a pointer
 * @p: pointer to a naturally-aligned 32-bit value
 */
static __always_inline __u32 __swab32p(const __u32 *p)
{
    return __swab32(*p);
}

#endif /* _UAPI_LINUX_SWAB_H */

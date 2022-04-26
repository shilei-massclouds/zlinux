/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_BYTEORDER_LITTLE_ENDIAN_H
#define _UAPI_LINUX_BYTEORDER_LITTLE_ENDIAN_H

#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif
#ifndef __LITTLE_ENDIAN_BITFIELD
#define __LITTLE_ENDIAN_BITFIELD
#endif

#include <linux/types.h>
#include <linux/swab.h>

#define __cpu_to_le16(x) ((__force __le16)(__u16)(x))

#define __cpu_to_be32(x) ((__force __be32)__swab32((x)))

#define __be32_to_cpu(x) __swab32((__force __u32)(__be32)(x))

static __always_inline __u32 __be32_to_cpup(const __be32 *p)
{
    return __swab32p((__u32 *)p);
}

#endif /* _UAPI_LINUX_BYTEORDER_LITTLE_ENDIAN_H */

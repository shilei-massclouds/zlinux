/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LIMITS_H
#define _LINUX_LIMITS_H

#include <uapi/linux/limits.h>
#include <linux/types.h>
#include <vdso/limits.h>

#define PHYS_ADDR_MAX   (~(phys_addr_t)0)

#define U32_MAX     ((u32)~0U)
#define U32_MIN     ((u32)0)
#define S32_MAX     ((s32)(U32_MAX >> 1))
#define S32_MIN     ((s32)(-S32_MAX - 1))
#define SIZE_MAX    (~(size_t)0)
#define U64_MAX     ((u64)~0ULL)
#define S64_MAX     ((s64)(U64_MAX >> 1))
#define S64_MIN     ((s64)(-S64_MAX - 1))

#endif /* _LINUX_LIMITS_H */

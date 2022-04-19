/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LIMITS_H
#define _LINUX_LIMITS_H

#include <linux/types.h>
#include <vdso/limits.h>

#define U32_MAX     ((u32)~0U)
#define U32_MIN     ((u32)0)
#define S32_MAX     ((s32)(U32_MAX >> 1))
#define S32_MIN     ((s32)(-S32_MAX - 1))
#define SIZE_MAX    (~(size_t)0)

#endif /* _LINUX_LIMITS_H */

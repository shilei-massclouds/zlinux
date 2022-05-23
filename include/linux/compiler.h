/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COMPILER_H
#define __LINUX_COMPILER_H

#include <linux/compiler_types.h>

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely_notrace(x)   likely(x)
#define unlikely_notrace(x) unlikely(x)

#ifndef __ASSEMBLY__

#ifdef __KERNEL__

#endif /* __KERNEL__ */

#endif /* __ASSEMBLY__ */

#include <asm/rwonce.h>

#endif /* __LINUX_COMPILER_H */

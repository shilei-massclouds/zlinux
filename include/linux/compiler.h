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

/* &a[0] degrades to a pointer: a different type from an array */
#define __must_be_array(a)  BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

/*
 * This is needed in functions which generate the stack canary, see
 * arch/x86/kernel/smpboot.c::start_secondary() for an example.
 */
#define prevent_tail_call_optimization()    mb()

#include <asm/rwonce.h>

#endif /* __LINUX_COMPILER_H */

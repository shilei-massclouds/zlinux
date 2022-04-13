/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H

#define __EXPORTED_HEADERS__
#include <uapi/linux/types.h>

#ifndef __ASSEMBLY__

typedef _Bool           bool;

/*
 * The following typedefs are also protected by individual ifdefs for
 * historical reasons:
 */
#ifndef _SIZE_T
#define _SIZE_T
typedef __kernel_size_t     size_t;
#endif

#if defined(__GNUC__)
typedef u64         uint64_t;
typedef u64         u_int64_t;
typedef s64         int64_t;
#endif

typedef u64 phys_addr_t;

typedef unsigned long   uintptr_t;

typedef struct {
    int counter;
} atomic_t;

#define ATOMIC_INIT(i) { (i) }

#endif /*  __ASSEMBLY__ */

#endif /* _LINUX_TYPES_H */

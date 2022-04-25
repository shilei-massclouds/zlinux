/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_H
#define _LINUX_MM_H

#ifdef __KERNEL__

#include <linux/bug.h>
#include <linux/pgtable.h>

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)

/* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
#define PAGE_ALIGNED(addr)  IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)

extern unsigned long max_mapnr;

static inline void set_max_mapnr(unsigned long limit)
{
    max_mapnr = limit;
}

#endif /* __KERNEL__ */

#endif /* _LINUX_MM_H */

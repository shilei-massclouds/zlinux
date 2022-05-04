/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_H
#define _LINUX_MM_H

#include <linux/bug.h>
#include <linux/pgtable.h>

#include <asm/page.h>

/* to align the pointer to the (next) page boundary */
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)

/* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
#define PAGE_ALIGNED(addr)  IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)

extern unsigned long max_mapnr;

static inline void set_max_mapnr(unsigned long limit)
{
    max_mapnr = limit;
}

void free_area_init(unsigned long *max_zone_pfn);

static inline void setup_nr_node_ids(void) {}

extern void get_pfn_range_for_nid(unsigned int nid,
                                  unsigned long *start_pfn, unsigned long *end_pfn);

#endif /* _LINUX_MM_H */

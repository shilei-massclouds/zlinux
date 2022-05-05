/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MEMREMAP_H_
#define _LINUX_MEMREMAP_H_

//#include <linux/range.h>
#include <linux/ioport.h>
//#include <linux/percpu-refcount.h>

/**
 * struct vmem_altmap - pre-allocated storage for vmemmap_populate
 * @base_pfn: base of the entire dev_pagemap mapping
 * @reserve: pages mapped, but reserved for driver use (relative to @base)
 * @free: free pages set aside in the mapping for memmap storage
 * @align: pages reserved to meet allocation alignments
 * @alloc: track pages consumed, private to vmemmap_populate()
 */
struct vmem_altmap {
    unsigned long base_pfn;
    const unsigned long end_pfn;
    const unsigned long reserve;
    unsigned long free;
    unsigned long align;
    unsigned long alloc;
};

#endif /* _LINUX_MEMREMAP_H_ */

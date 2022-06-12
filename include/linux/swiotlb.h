/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_SWIOTLB_H
#define __LINUX_SWIOTLB_H

//#include <linux/device.h>
//#include <linux/dma-direction.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/spinlock.h>

struct device;
struct page;
struct scatterlist;

enum swiotlb_force {
    SWIOTLB_NORMAL,     /* Default - depending on HW DMA mask etc. */
    SWIOTLB_FORCE,      /* swiotlb=force */
    SWIOTLB_NO_FORCE,   /* swiotlb=noforce */
};

/*
 * log of the size of each IO TLB slab.  The number of slabs is command line
 * controllable.
 */
#define IO_TLB_SHIFT 11
#define IO_TLB_SIZE (1 << IO_TLB_SHIFT)

/* default to 64MB */
#define IO_TLB_DEFAULT_SIZE (64UL<<20)

extern enum swiotlb_force swiotlb_force;

extern void swiotlb_init(int verbose);
int swiotlb_init_with_tbl(char *tlb, unsigned long nslabs, int verbose);

#endif /* __LINUX_SWIOTLB_H */

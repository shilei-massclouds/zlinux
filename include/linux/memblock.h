/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_MEMBLOCK_H
#define _LINUX_MEMBLOCK_H

#ifdef __KERNEL__

/*
 * Logical memory blocks.
 *
 * Copyright (C) 2001 Peter Bergner, IBM Corp.
 */

#include <linux/init.h>
#include <linux/mm.h>
//#include <asm/dma.h>

/**
 * enum memblock_flags - definition of memory region attributes
 * @MEMBLOCK_NONE: no special request
 * @MEMBLOCK_HOTPLUG: hotpluggable region
 * @MEMBLOCK_MIRROR: mirrored region
 * @MEMBLOCK_NOMAP: don't add to kernel direct mapping
 */
enum memblock_flags {
    MEMBLOCK_NONE       = 0x0,  /* No special request */
    MEMBLOCK_HOTPLUG    = 0x1,  /* hotpluggable region */
    MEMBLOCK_MIRROR     = 0x2,  /* mirrored region */
    MEMBLOCK_NOMAP      = 0x4,  /* don't add to kernel direct mapping */
};

/**
 * struct memblock_region - represents a memory region
 * @base: base address of the region
 * @size: size of the region
 * @flags: memory region attributes
 * @nid: NUMA node id
 */
struct memblock_region {
    phys_addr_t base;
    phys_addr_t size;
    enum memblock_flags flags;
};

/**
 * struct memblock_type - collection of memory regions of certain type
 * @cnt: number of regions
 * @max: size of the allocated array
 * @total_size: size of all regions
 * @regions: array of regions
 * @name: the memory type symbolic name
 */
struct memblock_type {
    unsigned long cnt;
    unsigned long max;
    phys_addr_t total_size;
    struct memblock_region *regions;
    char *name;
};

/**
 * struct memblock - memblock allocator metadata
 * @bottom_up: is bottom up direction?
 * @current_limit: physical address of the current allocation limit
 * @memory: usable memory regions
 * @reserved: reserved memory regions
 */
struct memblock {
    bool bottom_up;  /* is bottom up direction? */
    phys_addr_t current_limit;
    struct memblock_type memory;
    struct memblock_type reserved;
};

extern struct memblock memblock;
extern int memblock_debug;

#define memblock_dbg(fmt, ...) \
    if (memblock_debug) printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)

#define __init_memblock
#define __initdata_memblock

#define for_each_memblock(memblock_type, region)                    \
    for (region = memblock.memblock_type.regions;                   \
         region < (memblock.memblock_type.regions + memblock.memblock_type.cnt);    \
         region++)

/* Flags for memblock allocation APIs */
#define MEMBLOCK_ALLOC_ANYWHERE (~(phys_addr_t)0)

int memblock_remove(phys_addr_t base, phys_addr_t size);

#endif /* __KERNEL__ */

#endif /* _LINUX_MEMBLOCK_H */

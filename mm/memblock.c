// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Procedures for maintaining information about logical memory blocks.
 *
 * Peter Bergner, IBM Corp. June 2001.
 * Copyright (C) 2001 Peter Bergner.
 */

#include <linux/kernel.h>
//#include <linux/slab.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/poison.h>
#include <linux/pfn.h>
#if 0
#include <linux/debugfs.h>
#include <linux/kmemleak.h>
#include <linux/seq_file.h>
#endif
#include <linux/memblock.h>

#include <asm/sections.h>
//#include <linux/io.h>
#include <linux/errno.h>

#include "internal.h"

#define INIT_MEMBLOCK_REGIONS   128
#define INIT_PHYSMEM_REGIONS    4

#ifndef INIT_MEMBLOCK_RESERVED_REGIONS
# define INIT_MEMBLOCK_RESERVED_REGIONS INIT_MEMBLOCK_REGIONS
#endif

static struct memblock_region
memblock_memory_init_regions[INIT_MEMBLOCK_REGIONS]
__initdata_memblock;

static struct memblock_region
memblock_reserved_init_regions[INIT_MEMBLOCK_RESERVED_REGIONS]
__initdata_memblock;

struct memblock memblock __initdata_memblock = {
    .memory.regions = memblock_memory_init_regions,
    .memory.cnt     = 1,    /* empty dummy entry */
    .memory.max     = INIT_MEMBLOCK_REGIONS,
    .memory.name    = "memory",

    .reserved.regions   = memblock_reserved_init_regions,
    .reserved.cnt       = 1,    /* empty dummy entry */
    .reserved.max       = INIT_MEMBLOCK_RESERVED_REGIONS,
    .reserved.name      = "reserved",

    .bottom_up          = false,
    .current_limit      = MEMBLOCK_ALLOC_ANYWHERE,
};

int memblock_debug __initdata_memblock;

static int memblock_can_resize __initdata_memblock;

/* adjust *@size so that (@base + *@size) doesn't overflow, return new size */
static inline phys_addr_t
memblock_cap_size(phys_addr_t base, phys_addr_t *size)
{
    return *size = min(*size, PHYS_ADDR_MAX - base);
}

/**
 * memblock_double_array - double the size of the memblock regions array
 * @type: memblock type of the regions array being doubled
 * @new_area_start: starting address of memory range to avoid overlap with
 * @new_area_size: size of memory range to avoid overlap with
 *
 * Double the size of the @type regions array. If memblock is being used to
 * allocate memory for a new reserved regions array and there is a previously
 * allocated memory range [@new_area_start, @new_area_start + @new_area_size]
 * waiting to be reserved, ensure the memory used by the new array does
 * not overlap.
 *
 * Return:
 * 0 on success, -1 on failure.
 */
static int __init_memblock
memblock_double_array(struct memblock_type *type,
                      phys_addr_t new_area_start,
                      phys_addr_t new_area_size)
{
    struct memblock_region *new_array, *old_array;
    phys_addr_t old_alloc_size, new_alloc_size;
    phys_addr_t old_size, new_size, addr, new_end;
#if 0
    int use_slab = slab_is_available();
    int *in_slab;
#endif

    /* We don't allow resizing until we know about the reserved regions
     * of memory that aren't suitable for allocation
     */
    if (!memblock_can_resize)
        return -1;

    panic("Don't support memblock resize!\n");
    return 0;
}

/**
 * memblock_isolate_range - isolate given range into disjoint memblocks
 * @type: memblock type to isolate range for
 * @base: base of range to isolate
 * @size: size of range to isolate
 * @start_rgn: out parameter for the start of isolated region
 * @end_rgn: out parameter for the end of isolated region
 *
 * Walk @type and ensure that regions don't cross the boundaries defined by
 * [@base, @base + @size).  Crossing regions are split at the boundaries,
 * which may create at most two more regions.  The index of the first
 * region inside the range is returned in *@start_rgn and end in *@end_rgn.
 *
 * Return:
 * 0 on success, -errno on failure.
 */
static int __init_memblock
memblock_isolate_range(struct memblock_type *type,
                       phys_addr_t base, phys_addr_t size,
                       int *start_rgn, int *end_rgn)
{
#if 0
    int idx;
    struct memblock_region *rgn;
    phys_addr_t end = base + memblock_cap_size(base, &size);

    *start_rgn = *end_rgn = 0;

    if (!size)
        return 0;

    /* we'll create at most two more regions */
    while (type->cnt + 2 > type->max)
        if (memblock_double_array(type, base, size) < 0)
            return -ENOMEM;

#endif
    return 0;
}

static void __init_memblock
memblock_remove_region(struct memblock_type *type, unsigned long r)
{
#if 0
    type->total_size -= type->regions[r].size;
    memmove(&type->regions[r], &type->regions[r + 1],
            (type->cnt - (r + 1)) * sizeof(type->regions[r]));
    type->cnt--;

    /* Special case for empty arrays */
    if (type->cnt == 0) {
        WARN_ON(type->total_size != 0);
        type->cnt = 1;
        type->regions[0].base = 0;
        type->regions[0].size = 0;
        type->regions[0].flags = 0;
        memblock_set_region_node(&type->regions[0], MAX_NUMNODES);
    }
#endif
}

static int __init_memblock
memblock_remove_range(struct memblock_type *type,
                      phys_addr_t base, phys_addr_t size)
{
#if 0
    int start_rgn, end_rgn;
    int i, ret;

    ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
    if (ret)
        return ret;

    for (i = end_rgn - 1; i >= start_rgn; i--)
        memblock_remove_region(type, i);
#endif
    return 0;
}

int __init_memblock memblock_remove(phys_addr_t base, phys_addr_t size)
{
    phys_addr_t end = base + size - 1;

    memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
                 &base, &end, (void *)_RET_IP_);

    return memblock_remove_range(&memblock.memory, base, size);
}

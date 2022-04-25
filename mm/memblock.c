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
#include <linux/numa.h>

#include <asm/sections.h>
//#include <linux/io.h>
#include <linux/errno.h>
#include <linux/string.h>

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
    /*
    struct memblock_region *new_array, *old_array;
    phys_addr_t old_alloc_size, new_alloc_size;
    phys_addr_t old_size, new_size, addr, new_end;
    int use_slab = slab_is_available();
    int *in_slab;
    */

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
#if 0
static int __init_memblock
memblock_isolate_range(struct memblock_type *type,
                       phys_addr_t base, phys_addr_t size,
                       int *start_rgn, int *end_rgn)
{
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

    return 0;
}
#endif

#if 0
static void __init_memblock
memblock_remove_region(struct memblock_type *type, unsigned long r)
{
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
}
#endif

#if 0
static int __init_memblock
memblock_remove_range(struct memblock_type *type,
                      phys_addr_t base, phys_addr_t size)
{
    int start_rgn, end_rgn;
    int i, ret;

    ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
    if (ret)
        return ret;

    for (i = end_rgn - 1; i >= start_rgn; i--)
        memblock_remove_region(type, i);
    return 0;
}
#endif

int __init_memblock memblock_remove(phys_addr_t base, phys_addr_t size)
{
    panic("%s: Not-implemented!\n", __func__);
    return 0;

    /*
    phys_addr_t end = base + size - 1;

    memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
                 &base, &end, (void *)_RET_IP_);

    return memblock_remove_range(&memblock.memory, base, size);
    */
}

/**
 * memblock_insert_region - insert new memblock region
 * @type:   memblock type to insert into
 * @idx:    index for the insertion point
 * @base:   base address of the new region
 * @size:   size of the new region
 * @nid:    node id of the new region
 * @flags:  flags of the new region
 *
 * Insert new memblock region [@base, @base + @size) into @type at @idx.
 * @type must already have extra room to accommodate the new region.
 */
static void __init_memblock
memblock_insert_region(struct memblock_type *type,
                       int idx, phys_addr_t base,
                       phys_addr_t size,
                       int nid,
                       enum memblock_flags flags)
{
    struct memblock_region *rgn = &type->regions[idx];

    BUG_ON(type->cnt >= type->max);
    memmove(rgn + 1, rgn, (type->cnt - idx) * sizeof(*rgn));
    rgn->base = base;
    rgn->size = size;
    rgn->flags = flags;
    type->cnt++;
    type->total_size += size;
}

/**
 * memblock_merge_regions - merge neighboring compatible regions
 * @type: memblock type to scan
 *
 * Scan @type and merge neighboring compatible regions.
 */
static void __init_memblock
memblock_merge_regions(struct memblock_type *type)
{
    int i = 0;

    /* cnt never goes below 1 */
    while (i < type->cnt - 1) {
        struct memblock_region *this = &type->regions[i];
        struct memblock_region *next = &type->regions[i + 1];

        if (this->base + this->size != next->base ||
            this->flags != next->flags) {
            BUG_ON(this->base + this->size > next->base);
            i++;
            continue;
        }

        this->size += next->size;
        /* move forward from next + 1, index of which is i + 2 */
        memmove(next, next + 1, (type->cnt - (i + 2)) * sizeof(*next));
        type->cnt--;
    }
}

/**
 * memblock_add_range - add new memblock region
 * @type: memblock type to add new region into
 * @base: base address of the new region
 * @size: size of the new region
 * @nid: nid of the new region
 * @flags: flags of the new region
 *
 * Add new memblock region [@base, @base + @size) into @type.  The new region
 * is allowed to overlap with existing ones - overlaps don't affect already
 * existing regions.  @type is guaranteed to be minimal (all neighbouring
 * compatible regions are merged) after the addition.
 *
 * Return:
 * 0 on success, -errno on failure.
 */
static int __init_memblock
memblock_add_range(struct memblock_type *type,
                   phys_addr_t base, phys_addr_t size,
                   int nid, enum memblock_flags flags)
{
    int idx, nr_new;
    struct memblock_region *rgn;
    bool insert = false;
    phys_addr_t obase = base;
    phys_addr_t end = base + memblock_cap_size(base, &size);

    if (!size)
        return 0;

    /* special case for empty array */
    if (type->regions[0].size == 0) {
        WARN_ON(type->cnt != 1 || type->total_size);
        type->regions[0].base = base;
        type->regions[0].size = size;
        type->regions[0].flags = flags;
        type->total_size = size;
        return 0;
    }

repeat:
    /*
     * The following is executed twice.  Once with %false @insert and
     * then with %true.  The first counts the number of regions needed
     * to accommodate the new area.  The second actually inserts them.
     */
    base = obase;
    nr_new = 0;

    for_each_memblock_type(idx, type, rgn) {
        phys_addr_t rbase = rgn->base;
        phys_addr_t rend = rbase + rgn->size;

        if (rbase >= end)
            break;
        if (rend <= base)
            continue;
        /*
         * @rgn overlaps.  If it separates the lower part of new
         * area, insert that portion.
         */
        if (rbase > base) {
            WARN_ON(flags != rgn->flags);
            nr_new++;
            if (insert)
                memblock_insert_region(type, idx++,
                                       base, rbase - base, nid, flags);
        }
        /* area below @rend is dealt with, forget about it */
        base = min(rend, end);
    }

    /* insert the remaining portion */
    if (base < end) {
        nr_new++;
        if (insert)
            memblock_insert_region(type, idx, base, end - base, nid, flags);
    }

    if (!nr_new)
        return 0;

    /*
     * If this was the first round, resize array and repeat for actual
     * insertions; otherwise, merge and return.
     */
    if (!insert) {
        while (type->cnt + nr_new > type->max)
            if (memblock_double_array(type, obase, size) < 0)
                return -ENOMEM;
        insert = true;
        goto repeat;
    } else {
        memblock_merge_regions(type);
        return 0;
    }
}

/**
 * memblock_add - add new memblock region
 * @base: base address of the new region
 * @size: size of the new region
 *
 * Add new memblock region [@base, @base + @size) to the "memory"
 * type. See memblock_add_range() description for mode details
 *
 * Return:
 * 0 on success, -errno on failure.
 */
int __init_memblock memblock_add(phys_addr_t base, phys_addr_t size)
{
    phys_addr_t end = base + size - 1;

    memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
                 &base, &end, (void *)_RET_IP_);

    return memblock_add_range(&memblock.memory, base, size, MAX_NUMNODES, 0);
}

int __init_memblock memblock_reserve(phys_addr_t base, phys_addr_t size)
{
    phys_addr_t end = base + size - 1;

    memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
                 &base, &end, (void *)_RET_IP_);

    return memblock_add_range(&memblock.reserved, base, size, MAX_NUMNODES, 0);
}

void __init memblock_allow_resize(void)
{
    memblock_can_resize = 1;
}

void __init_memblock __memblock_dump_all(void)
{
    pr_info("MEMBLOCK configuration:\n");
    pr_info(" memory size = %pa reserved size = %pa\n",
            &memblock.memory.total_size,
            &memblock.reserved.total_size);

    /*
    memblock_dump(&memblock.memory);
    memblock_dump(&memblock.reserved);
    */
}

static int __init early_memblock(char *p)
{
    if (p && strstr(p, "debug"))
        memblock_debug = 1;
    return 0;
}
early_param("memblock", early_memblock);

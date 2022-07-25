// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Procedures for maintaining information about logical memory blocks.
 *
 * Peter Bergner, IBM Corp. June 2001.
 * Copyright (C) 2001 Peter Bergner.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
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
#include <linux/io.h>
#include <linux/errno.h>
#include <linux/string.h>

#include "internal.h"

#define INIT_MEMBLOCK_REGIONS   128
#define INIT_PHYSMEM_REGIONS    4

#ifndef INIT_MEMBLOCK_RESERVED_REGIONS
# define INIT_MEMBLOCK_RESERVED_REGIONS INIT_MEMBLOCK_REGIONS
#endif

unsigned long max_low_pfn;
unsigned long min_low_pfn;
unsigned long max_pfn;

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

struct pglist_data __refdata contig_page_data;
EXPORT_SYMBOL(contig_page_data);

int memblock_debug __initdata_memblock;

static int memblock_can_resize __initdata_memblock;

static bool system_has_some_mirror __initdata_memblock = false;

static int memblock_memory_in_slab __initdata_memblock = 0;
static int memblock_reserved_in_slab __initdata_memblock = 0;

/*
 * keep a pointer to &memblock.memory in the text section to use it in
 * __next_mem_range() and its helpers.
 *  For architectures that do not keep memblock data after init, this
 * pointer will be reset to NULL at memblock_discard()
 */
static __refdata struct memblock_type *memblock_memory = &memblock.memory;

static enum memblock_flags __init_memblock choose_memblock_flags(void)
{
    return system_has_some_mirror ? MEMBLOCK_MIRROR : MEMBLOCK_NONE;
}

/* adjust *@size so that (@base + *@size) doesn't overflow, return new size */
static inline phys_addr_t
memblock_cap_size(phys_addr_t base, phys_addr_t *size)
{
    return *size = min(*size, PHYS_ADDR_MAX - base);
}

static phys_addr_t __init_memblock
__memblock_find_range_top_down(phys_addr_t start, phys_addr_t end,
                               phys_addr_t size, phys_addr_t align,
                               int nid, enum memblock_flags flags)
{
    u64 i;
    phys_addr_t this_start, this_end, cand;

    for_each_free_mem_range_reverse(i, nid, flags,
                                    &this_start, &this_end, NULL) {

        this_start = clamp(this_start, start, end);
        this_end = clamp(this_end, start, end);

        if (this_end < size)
            continue;

        cand = round_down(this_end - size, align);
        if (cand >= this_start)
            return cand;
    }

    return 0;
}

static phys_addr_t __init_memblock
memblock_find_in_range_node(phys_addr_t size, phys_addr_t align,
                            phys_addr_t start, phys_addr_t end,
                            int nid, enum memblock_flags flags)
{
    phys_addr_t kernel_end;

    /* pump up @end */
    if (end == MEMBLOCK_ALLOC_ACCESSIBLE || end == MEMBLOCK_ALLOC_KASAN)
        end = memblock.current_limit;

    /* avoid allocating the first page */
    start = max_t(phys_addr_t, start, PAGE_SIZE);
    end = max(start, end);
    kernel_end = __pa_symbol(_end);

    /*
     * try bottom-up allocation only when bottom-up mode
     * is set and @end is above the kernel image.
     */
    if (memblock_bottom_up() && end > kernel_end) {
        panic("%s: NOT-implemented!\n", __func__);
    }

    return __memblock_find_range_top_down(start, end, size, align, nid, flags);
}

/**
 * memblock_find_in_range - find free area in given range
 * @start: start of candidate range
 * @end: end of candidate range, can be %MEMBLOCK_ALLOC_ANYWHERE or
 *       %MEMBLOCK_ALLOC_ACCESSIBLE
 * @size: size of free area to find
 * @align: alignment of free area to find
 *
 * Find @size free area aligned to @align in the specified range.
 *
 * Return:
 * Found address on success, 0 on failure.
 */
static phys_addr_t __init_memblock
memblock_find_in_range(phys_addr_t start, phys_addr_t end,
                       phys_addr_t size, phys_addr_t align)
{
    phys_addr_t ret;
    enum memblock_flags flags = choose_memblock_flags();

again:
    ret = memblock_find_in_range_node(size, align, start, end,
                                      NUMA_NO_NODE, flags);

    if (!ret && (flags & MEMBLOCK_MIRROR)) {
        pr_warn("Could not allocate %pap bytes of mirrored memory\n", &size);
        flags &= ~MEMBLOCK_MIRROR;
        goto again;
    }

    return ret;
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
    memblock_set_region_node(rgn, nid);
    type->cnt++;
    type->total_size += size;
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
    int *in_slab;
    phys_addr_t old_alloc_size, new_alloc_size;
    phys_addr_t old_size, new_size, addr, new_end;
    struct memblock_region *new_array, *old_array;
    /*
    int use_slab = slab_is_available();
    */

    /* We don't allow resizing until we know about the reserved regions
     * of memory that aren't suitable for allocation
     */
    if (!memblock_can_resize)
        return -1;

    /* Calculate new doubled size */
    old_size = type->max * sizeof(struct memblock_region);
    new_size = old_size << 1;
    /*
     * We need to allocated new one align to PAGE_SIZE,
     *   so we can free them completely later.
     */
    old_alloc_size = PAGE_ALIGN(old_size);
    new_alloc_size = PAGE_ALIGN(new_size);

    /* Retrieve the slab flag */
    if (type == &memblock.memory)
        in_slab = &memblock_memory_in_slab;
    else
        in_slab = &memblock_reserved_in_slab;

#if 0
    /* Try to find some space for it */
    if (use_slab) {
        new_array = kmalloc(new_size, GFP_KERNEL);
        addr = new_array ? __pa(new_array) : 0;
    } else {
#endif
        /* only exclude range when trying to double reserved.regions */
        if (type != &memblock.reserved)
            new_area_start = new_area_size = 0;

        addr = memblock_find_in_range(new_area_start + new_area_size,
                                      memblock.current_limit,
                                      new_alloc_size, PAGE_SIZE);
        if (!addr && new_area_size)
            addr = memblock_find_in_range(0,
                min(new_area_start, memblock.current_limit),
                new_alloc_size, PAGE_SIZE);

        new_array = addr ? __va(addr) : NULL;
#if 0
    }
#endif
    if (!addr) {
        pr_err("memblock: Failed to double %s array from %ld to %ld entries !\n",
               type->name, type->max, type->max * 2);
        return -1;
    }

    new_end = addr + new_size - 1;
    memblock_dbg("memblock: %s is doubled to %ld at [%pa-%pa]",
                 type->name, type->max * 2, &addr, &new_end);

    /*
     * Found space, we now need to move the array over before we add the
     * reserved region since it may be our reserved array itself that is
     * full.
     */
    memcpy(new_array, type->regions, old_size);
    memset(new_array + type->max, 0, old_size);
    old_array = type->regions;
    type->regions = new_array;
    type->max <<= 1;

#if 0
    /* Free old array. We needn't free it if the array is the static one */
    if (*in_slab)
        kfree(old_array);
    else if (old_array != memblock_memory_init_regions &&
             old_array != memblock_reserved_init_regions)
        memblock_free(old_array, old_alloc_size);

    /*
     * Reserve the new array if that comes from the memblock.  Otherwise, we
     * needn't do it
     */
    if (!use_slab)
        BUG_ON(memblock_reserve(addr, new_alloc_size));

    /* Update slab flag */
    *in_slab = use_slab;
#endif
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

    for_each_memblock_type(idx, type, rgn) {
        phys_addr_t rbase = rgn->base;
        phys_addr_t rend = rbase + rgn->size;

        if (rbase >= end)
            break;
        if (rend <= base)
            continue;

        if (rbase < base) {
            /*
             * @rgn intersects from below.  Split and continue
             * to process the next region - the new top half.
             */
            rgn->base = base;
            rgn->size -= base - rbase;
            type->total_size -= base - rbase;
            memblock_insert_region(type, idx, rbase, base - rbase,
                                   memblock_get_region_node(rgn), rgn->flags);
        } else if (rend > end) {
            /*
             * @rgn intersects from above.  Split and redo the
             * current region - the new bottom half.
             */
            rgn->base = end;
            rgn->size -= end - rbase;
            type->total_size -= end - rbase;
            memblock_insert_region(type, idx--, rbase, end - rbase,
                                   memblock_get_region_node(rgn), rgn->flags);
        } else {
            /* @rgn is fully contained, record it */
            if (!*end_rgn)
                *start_rgn = idx;
            *end_rgn = idx + 1;
        }
    }

    return 0;
}

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

static int __init_memblock
memblock_remove_range(struct memblock_type *type,
                      phys_addr_t base, phys_addr_t size)
{
    int i, ret;
    int start_rgn, end_rgn;

    ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
    if (ret)
        return ret;

    for (i = end_rgn - 1; i >= start_rgn; i--)
        memblock_remove_region(type, i);
    return 0;
}

int __init_memblock memblock_remove(phys_addr_t base, phys_addr_t size)
{
    phys_addr_t end = base + size - 1;

    memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
                 &base, &end, (void *)_RET_IP_);

    return memblock_remove_range(&memblock.memory, base, size);
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

static void __init_memblock memblock_dump(struct memblock_type *type)
{
    int idx;
    enum memblock_flags flags;
    phys_addr_t base, end, size;
    struct memblock_region *rgn;

    pr_info(" %s.cnt  = 0x%lx\n", type->name, type->cnt);

    for_each_memblock_type(idx, type, rgn) {
        char nid_buf[32] = "";

        base = rgn->base;
        size = rgn->size;
        end = base + size - 1;
        flags = rgn->flags;

        pr_info(" %s[%#x]\t[%pa-%pa], %pa bytes%s flags: %#x\n",
                type->name, idx, &base, &end, &size, nid_buf, flags);
    }
}

void __init_memblock __memblock_dump_all(void)
{
    pr_info("MEMBLOCK configuration:\n");
    pr_info(" memory size = %pa reserved size = %pa\n",
            &memblock.memory.total_size,
            &memblock.reserved.total_size);

    memblock_dump(&memblock.memory);
    memblock_dump(&memblock.reserved);
}

void __init_memblock memblock_dump_all(void)
{
    if (memblock_debug)
        __memblock_dump_all();
}

phys_addr_t __init
memblock_alloc_range_nid(phys_addr_t size, phys_addr_t align,
                         phys_addr_t start, phys_addr_t end,
                         int nid, bool exact_nid)
{
    phys_addr_t found;
    enum memblock_flags flags = choose_memblock_flags();

    if (WARN_ONCE(nid == MAX_NUMNODES,"Usage of MAX_NUMNODES is deprecated. Use NUMA_NO_NODE instead\n"))
        nid = NUMA_NO_NODE;

    if (!align) {
        /* Can't use WARNs this early in boot on powerpc */
        //dump_stack();
        align = SMP_CACHE_BYTES;
    }

again:
    found = memblock_find_in_range_node(size, align, start, end, nid, flags);
    if (found && !memblock_reserve(found, size))
        goto done;

    if (nid != NUMA_NO_NODE && !exact_nid) {
        found = memblock_find_in_range_node(size, align, start, end,
                                            NUMA_NO_NODE, flags);
        if (found && !memblock_reserve(found, size))
            goto done;
    }

    if (flags & MEMBLOCK_MIRROR) {
        flags &= ~MEMBLOCK_MIRROR;
        pr_warn("Could not allocate %pap bytes of mirrored memory\n", &size);
        goto again;
    }

    return 0;

done:
    return found;
}

/**
 * memblock_phys_alloc_range - allocate a memory block inside specified range
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @start: the lower bound of the memory region to allocate (physical address)
 * @end: the upper bound of the memory region to allocate (physical address)
 *
 * Allocate @size bytes in the between @start and @end.
 *
 * Return: physical address of the allocated memory block on success,
 * %0 on failure.
 */
phys_addr_t __init
memblock_phys_alloc_range(phys_addr_t size, phys_addr_t align,
                          phys_addr_t start, phys_addr_t end)
{
    return memblock_alloc_range_nid(size, align, start, end,
                                    NUMA_NO_NODE, false);
}

static bool
should_skip_region(struct memblock_region *m, int nid, int flags)
{
    int m_nid = memblock_get_region_node(m);

    /* only memory regions are associated with nodes, check it */
    if (nid != NUMA_NO_NODE && nid != m_nid)
        return true;

    /* skip nomap memory unless we were asked for it explicitly */
    if (!(flags & MEMBLOCK_NOMAP) && memblock_is_nomap(m))
        return true;

    return false;
}

void __next_mem_range(u64 *idx, int nid, enum memblock_flags flags,
                      struct memblock_type *type_a,
                      struct memblock_type *type_b,
                      phys_addr_t *out_start, phys_addr_t *out_end,
                      int *out_nid)
{
    int idx_a = *idx & 0xffffffff;
    int idx_b = *idx >> 32;

    if (WARN_ONCE(nid == MAX_NUMNODES,
        "Usage of MAX_NUMNODES is deprecated. Use NUMA_NO_NODE instead\n"))
        nid = NUMA_NO_NODE;

    for (; idx_a < type_a->cnt; idx_a++) {
        struct memblock_region *m = &type_a->regions[idx_a];

        phys_addr_t m_start = m->base;
        phys_addr_t m_end = m->base + m->size;
        int m_nid = memblock_get_region_node(m);

        if (should_skip_region(m, nid, flags))
            continue;

        if (!type_b) {
            if (out_start)
                *out_start = m_start;
            if (out_end)
                *out_end = m_end;
            if (out_nid)
                *out_nid = m_nid;
            idx_a++;
            *idx = (u32)idx_a | (u64)idx_b << 32;
            return;
        }

        /* scan areas before each reservation */
        for (; idx_b < type_b->cnt + 1; idx_b++) {
            struct memblock_region *r;
            phys_addr_t r_start;
            phys_addr_t r_end;

            r = &type_b->regions[idx_b];
            r_start = idx_b ? r[-1].base + r[-1].size : 0;
            r_end = idx_b < type_b->cnt ?
                r->base : PHYS_ADDR_MAX;

            /*
             * if idx_b advanced past idx_a,
             * break out to advance idx_a
             */
            if (r_start >= m_end)
                break;
            /* if the two regions intersect, we're done */
            if (m_start < r_end) {
                if (out_start)
                    *out_start =
                        max(m_start, r_start);
                if (out_end)
                    *out_end = min(m_end, r_end);
                if (out_nid)
                    *out_nid = m_nid;
                /*
                 * The region which ends first is
                 * advanced for the next iteration.
                 */
                if (m_end <= r_end)
                    idx_a++;
                else
                    idx_b++;
                *idx = (u32)idx_a | (u64)idx_b << 32;
                return;
            }
        }
    }

    /* signal end of iteration */
    *idx = ULLONG_MAX;
}

/**
 * __next_mem_range_rev - generic next function for for_each_*_range_rev()
 *
 * @idx: pointer to u64 loop variable
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @type_a: pointer to memblock_type from where the range is taken
 * @type_b: pointer to memblock_type which excludes memory from being taken
 * @out_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @out_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @out_nid: ptr to int for nid of the range, can be %NULL
 *
 * Finds the next range from type_a which is not marked as unsuitable
 * in type_b.
 *
 * Reverse of __next_mem_range().
 */
void __init_memblock
__next_mem_range_rev(u64 *idx, int nid,
                     enum memblock_flags flags,
                     struct memblock_type *type_a,
                     struct memblock_type *type_b,
                     phys_addr_t *out_start, phys_addr_t *out_end,
                     int *out_nid)
{
    int idx_a = *idx & 0xffffffff;
    int idx_b = *idx >> 32;

    if (WARN_ONCE(nid == MAX_NUMNODES, "Usage of MAX_NUMNODES is deprecated. Use NUMA_NO_NODE instead\n"))
        nid = NUMA_NO_NODE;

    if (*idx == (u64)ULLONG_MAX) {
        idx_a = type_a->cnt - 1;
        if (type_b != NULL)
            idx_b = type_b->cnt;
        else
            idx_b = 0;
    }

    for (; idx_a >= 0; idx_a--) {
        struct memblock_region *m = &type_a->regions[idx_a];

        phys_addr_t m_start = m->base;
        phys_addr_t m_end = m->base + m->size;
        int m_nid = memblock_get_region_node(m);

        if (should_skip_region(m, nid, flags))
            continue;

        if (!type_b) {
            if (out_start)
                *out_start = m_start;
            if (out_end)
                *out_end = m_end;
            if (out_nid)
                *out_nid = m_nid;
            idx_a--;
            *idx = (u32)idx_a | (u64)idx_b << 32;
            return;
        }

        /* scan areas before each reservation */
        for (; idx_b >= 0; idx_b--) {
            struct memblock_region *r;
            phys_addr_t r_start;
            phys_addr_t r_end;

            r = &type_b->regions[idx_b];
            r_start = idx_b ? r[-1].base + r[-1].size : 0;
            r_end = idx_b < type_b->cnt ? r->base : PHYS_ADDR_MAX;
            /*
             * if idx_b advanced past idx_a,
             * break out to advance idx_a
             */

            if (r_end <= m_start)
                break;
            /* if the two regions intersect, we're done */
            if (m_end > r_start) {
                if (out_start)
                    *out_start = max(m_start, r_start);
                if (out_end)
                    *out_end = min(m_end, r_end);
                if (out_nid)
                    *out_nid = m_nid;
                if (m_start >= r_start)
                    idx_a--;
                else
                    idx_b--;
                *idx = (u32)idx_a | (u64)idx_b << 32;
                return;
            }
        }
    }
    /* signal end of iteration */
    *idx = ULLONG_MAX;
}

static void * __init
memblock_alloc_internal(phys_addr_t size, phys_addr_t align,
                        phys_addr_t min_addr, phys_addr_t max_addr,
                        int nid, bool exact_nid)
{
    phys_addr_t alloc;

    /*
     * Detect any accidental use of these APIs after slab is ready, as at
     * this moment memblock may be deinitialized already and its
     * internal data may be destroyed (after execution of memblock_free_all)
     */
#if 0
    if (WARN_ON_ONCE(slab_is_available()))
        return kzalloc_node(size, GFP_NOWAIT, nid);
#endif

    if (max_addr > memblock.current_limit)
        max_addr = memblock.current_limit;

    alloc = memblock_alloc_range_nid(size, align, min_addr, max_addr,
                                     nid, exact_nid);

    /* retry allocation without lower limit */
    if (!alloc && min_addr)
        alloc = memblock_alloc_range_nid(size, align, 0, max_addr,
                                         nid, exact_nid);

    if (!alloc)
        return NULL;

    return phys_to_virt(alloc);
}

/**
 * memblock_alloc_try_nid - allocate boot memory block
 * @size: size of memory block to be allocated in bytes
 * @align: alignment of the region and block's size
 * @min_addr: the lower bound of the memory region from where the allocation
 *    is preferred (phys address)
 * @max_addr: the upper bound of the memory region from where the allocation
 *        is preferred (phys address), or %MEMBLOCK_ALLOC_ACCESSIBLE to
 *        allocate only from memory limited by memblock.current_limit value
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * Public function, provides additional debug information (including caller
 * info), if enabled. This function zeroes the allocated memory.
 *
 * Return:
 * Virtual address of allocated memory block on success, NULL on failure.
 */
void * __init
memblock_alloc_try_nid(phys_addr_t size, phys_addr_t align,
                       phys_addr_t min_addr, phys_addr_t max_addr,
                       int nid)
{
    void *ptr;

    memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n",
                 __func__, (u64)size, (u64)align, nid, &min_addr,
                 &max_addr, (void *)_RET_IP_);

    ptr = memblock_alloc_internal(size, align,
                                  min_addr, max_addr, nid, false);
    if (ptr)
        memset(ptr, 0, size);

    return ptr;
}

/* lowest address */
phys_addr_t __init_memblock memblock_start_of_DRAM(void)
{
    return memblock.memory.regions[0].base;
}

phys_addr_t __init_memblock memblock_end_of_DRAM(void)
{
    int idx = memblock.memory.cnt - 1;

    return (memblock.memory.regions[idx].base +
            memblock.memory.regions[idx].size);
}

/*
 * Common iterator interface used to define for_each_mem_pfn_range().
 */
void __init_memblock
__next_mem_pfn_range(int *idx, int nid,
                     unsigned long *out_start_pfn, unsigned long *out_end_pfn,
                     int *out_nid)
{
    int r_nid;
    struct memblock_region *r;
    struct memblock_type *type = &memblock.memory;

    while (++*idx < type->cnt) {
        r = &type->regions[*idx];
        r_nid = memblock_get_region_node(r);

        if (PFN_UP(r->base) >= PFN_DOWN(r->base + r->size))
            continue;
        if (nid == MAX_NUMNODES || nid == r_nid)
            break;
    }
    if (*idx >= type->cnt) {
        *idx = -1;
        return;
    }

    if (out_start_pfn)
        *out_start_pfn = PFN_UP(r->base);
    if (out_end_pfn)
        *out_end_pfn = PFN_DOWN(r->base + r->size);
    if (out_nid)
        *out_nid = r_nid;
}

void * __init
memblock_alloc_try_nid_raw(phys_addr_t size, phys_addr_t align,
                           phys_addr_t min_addr, phys_addr_t max_addr, int nid)
{
    memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n",
                 __func__, (u64)size, (u64)align, nid, &min_addr,
                 &max_addr, (void *)_RET_IP_);

    return memblock_alloc_internal(size, align, min_addr, max_addr, nid, false);
}

void * __init
memblock_alloc_exact_nid_raw(phys_addr_t size, phys_addr_t align,
                             phys_addr_t min_addr, phys_addr_t max_addr, int nid)
{
    memblock_dbg("%s: %llu bytes align=0x%llx nid=%d from=%pa max_addr=%pa %pS\n",
                 __func__, (u64)size, (u64)align, nid, &min_addr,
                 &max_addr, (void *)_RET_IP_);

    return memblock_alloc_internal(size, align, min_addr, max_addr, nid, true);
}

void reset_node_managed_pages(pg_data_t *pgdat)
{
    struct zone *z;

    for (z = pgdat->node_zones; z < pgdat->node_zones + MAX_NR_ZONES; z++)
        atomic_long_set(&z->managed_pages, 0);
}

static int reset_managed_pages_done __initdata;

void __init reset_all_zones_managed_pages(void)
{
    struct pglist_data *pgdat;

    if (reset_managed_pages_done)
        return;

    for_each_online_pgdat(pgdat)
        reset_node_managed_pages(pgdat);

    reset_managed_pages_done = 1;
}

static void __init memmap_init_reserved_pages(void)
{
    u64 i;
    phys_addr_t start, end;
    struct memblock_region *region;

    /* initialize struct pages for the reserved regions */
    for_each_reserved_mem_range(i, &start, &end)
        reserve_bootmem_region(start, end);

    /* and also treat struct pages for the NOMAP regions as PageReserved */
    for_each_mem_region(region) {
        if (memblock_is_nomap(region)) {
            start = region->base;
            end = start + region->size;
            reserve_bootmem_region(start, end);
        }
    }
}

static void __init
__free_pages_memory(unsigned long start, unsigned long end)
{
    int order;

    while (start < end) {
        order = min(MAX_ORDER - 1UL, __ffs(start));

        while (start + (1UL << order) > end)
            order--;

        memblock_free_pages(pfn_to_page(start), start, order);

        start += (1UL << order);
    }
}

static unsigned long __init
__free_memory_core(phys_addr_t start, phys_addr_t end)
{
    unsigned long start_pfn = PFN_UP(start);
    unsigned long end_pfn = min_t(unsigned long,
                                  PFN_DOWN(end), max_low_pfn);

    if (start_pfn >= end_pfn)
        return 0;

    __free_pages_memory(start_pfn, end_pfn);

    return end_pfn - start_pfn;
}

/**
 * memblock_setclr_flag - set or clear flag for a memory region
 * @base: base address of the region
 * @size: size of the region
 * @set: set or clear the flag
 * @flag: the flag to update
 *
 * This function isolates region [@base, @base + @size), and sets/clears flag
 *
 * Return: 0 on success, -errno on failure.
 */
static int __init_memblock
memblock_setclr_flag(phys_addr_t base, phys_addr_t size, int set, int flag)
{
    int i, ret, start_rgn, end_rgn;
    struct memblock_type *type = &memblock.memory;

    ret = memblock_isolate_range(type, base, size, &start_rgn, &end_rgn);
    if (ret)
        return ret;

    for (i = start_rgn; i < end_rgn; i++) {
        struct memblock_region *r = &type->regions[i];

        if (set)
            r->flags |= flag;
        else
            r->flags &= ~flag;
    }

    memblock_merge_regions(type);
    return 0;
}

/**
 * memblock_clear_hotplug - Clear flag MEMBLOCK_HOTPLUG for a specified region.
 * @base: the base phys addr of the region
 * @size: the size of the region
 *
 * Return: 0 on success, -errno on failure.
 */
int __init_memblock memblock_clear_hotplug(phys_addr_t base, phys_addr_t size)
{
    return memblock_setclr_flag(base, size, 0, MEMBLOCK_HOTPLUG);
}

static unsigned long __init free_low_memory_core_early(void)
{
    u64 i;
    phys_addr_t start, end;
    unsigned long count = 0;

    memblock_clear_hotplug(0, -1);

    memmap_init_reserved_pages();

    /*
     * We need to use NUMA_NO_NODE instead of NODE_DATA(0)->node_id
     *  because in some case like Node0 doesn't have RAM installed
     *  low ram will be on Node1
     */
    for_each_free_mem_range(i, NUMA_NO_NODE, MEMBLOCK_NONE,
                            &start, &end, NULL)
        count += __free_memory_core(start, end);

    return count;
}

/**
 * memblock_free_all - release free pages to the buddy allocator
 */
void __init memblock_free_all(void)
{
    unsigned long pages;

    reset_all_zones_managed_pages();

    pages = free_low_memory_core_early();
    totalram_pages_add(pages);
}

static phys_addr_t __init_memblock __find_max_addr(phys_addr_t limit)
{
    struct memblock_region *r;
    phys_addr_t max_addr = PHYS_ADDR_MAX;

    /*
     * translate the memory @limit size into the max address within one of
     * the memory memblock regions, if the @limit exceeds the total size
     * of those regions, max_addr will keep original value PHYS_ADDR_MAX
     */
    for_each_mem_region(r) {
        if (limit <= r->size) {
            max_addr = r->base + limit;
            break;
        }
        limit -= r->size;
    }

    return max_addr;
}

void __init memblock_enforce_memory_limit(phys_addr_t limit)
{
    phys_addr_t max_addr;

    if (!limit)
        return;

    max_addr = __find_max_addr(limit);

    /* @limit exceeds the total size of the memory, do nothing */
    if (max_addr == PHYS_ADDR_MAX)
        return;

    /* truncate both memory and reserved regions */
    memblock_remove_range(&memblock.memory, max_addr, PHYS_ADDR_MAX);
    memblock_remove_range(&memblock.reserved, max_addr, PHYS_ADDR_MAX);
}

/**
 * memblock_phys_free - free boot memory block
 * @base: phys starting address of the  boot memory block
 * @size: size of the boot memory block in bytes
 *
 * Free boot memory block previously allocated by memblock_alloc_xx() API.
 * The freeing memory will not be released to the buddy allocator.
 */
int __init_memblock memblock_phys_free(phys_addr_t base, phys_addr_t size)
{
    phys_addr_t end = base + size - 1;

    memblock_dbg("%s: [%pa-%pa] %pS\n", __func__,
                 &base, &end, (void *)_RET_IP_);

    return memblock_remove_range(&memblock.reserved, base, size);
}

/**
 * memblock_free - free boot memory allocation
 * @ptr: starting address of the  boot memory allocation
 * @size: size of the boot memory block in bytes
 *
 * Free boot memory block previously allocated by memblock_alloc_xx() API.
 * The freeing memory will not be released to the buddy allocator.
 */
void __init_memblock memblock_free(void *ptr, size_t size)
{
    if (ptr)
        memblock_phys_free(__pa(ptr), size);
}

static int __init early_memblock(char *p)
{
    if (p && strstr(p, "debug"))
        memblock_debug = 1;
    return 0;
}
early_param("memblock", early_memblock);

static int __init_memblock
memblock_search(struct memblock_type *type, phys_addr_t addr)
{
    unsigned int left = 0, right = type->cnt;

    do {
        unsigned int mid = (right + left) / 2;

        if (addr < type->regions[mid].base)
            right = mid;
        else if (addr >= (type->regions[mid].base + type->regions[mid].size))
            left = mid + 1;
        else
            return mid;
    } while (left < right);
    return -1;
}

bool __init_memblock memblock_is_memory(phys_addr_t addr)
{
    return memblock_search(&memblock.memory, addr) != -1;
}

/**
 * memblock_free_late - free pages directly to buddy allocator
 * @base: phys starting address of the  boot memory block
 * @size: size of the boot memory block in bytes
 *
 * This is only useful when the memblock allocator has already been torn
 * down, but we are still initializing the system.  Pages are released directly
 * to the buddy allocator.
 */
void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
{
    phys_addr_t cursor, end;

    end = base + size - 1;
    memblock_dbg("%s: [%pa-%pa] %pS\n",
                 __func__, &base, &end, (void *)_RET_IP_);
    cursor = PFN_UP(base);
    end = PFN_DOWN(base + size);

    for (; cursor < end; cursor++) {
        memblock_free_pages(pfn_to_page(cursor), cursor, 0);
        totalram_pages_inc();
    }
}

/**
 * memblock_discard - discard memory and reserved arrays if they were allocated
 */
void __init memblock_discard(void)
{
    phys_addr_t addr, size;

    if (memblock.reserved.regions != memblock_reserved_init_regions) {
        addr = __pa(memblock.reserved.regions);
        size = PAGE_ALIGN(sizeof(struct memblock_region) *
                          memblock.reserved.max);
        if (memblock_reserved_in_slab)
            kfree(memblock.reserved.regions);
        else
            memblock_free_late(addr, size);
    }

    if (memblock.memory.regions != memblock_memory_init_regions) {
        addr = __pa(memblock.memory.regions);
        size = PAGE_ALIGN(sizeof(struct memblock_region) *
                          memblock.memory.max);
        if (memblock_memory_in_slab)
            kfree(memblock.memory.regions);
        else
            memblock_free_late(addr, size);
    }

    memblock_memory = NULL;
}

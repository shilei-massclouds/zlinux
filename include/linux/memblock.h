/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _LINUX_MEMBLOCK_H
#define _LINUX_MEMBLOCK_H

/*
 * Logical memory blocks.
 *
 * Copyright (C) 2001 Peter Bergner, IBM Corp.
 */

#include <linux/init.h>
#include <linux/mm.h>
#include <asm/dma.h>

/* Flags for memblock allocation APIs */
#define MEMBLOCK_ALLOC_ANYWHERE (~(phys_addr_t)0)
#define MEMBLOCK_ALLOC_ACCESSIBLE   0
#define MEMBLOCK_ALLOC_KASAN        1

/* We are using top down, so it is safe to use 0 here */
#define MEMBLOCK_LOW_LIMIT 0

#ifndef ARCH_LOW_ADDRESS_LIMIT
#define ARCH_LOW_ADDRESS_LIMIT  0xffffffffUL
#endif

#define __init_memblock __meminit
#define __initdata_memblock __meminitdata
void memblock_discard(void);

extern void *
alloc_large_system_hash(const char *tablename,
                        unsigned long bucketsize,
                        unsigned long numentries,
                        int scale,
                        int flags,
                        unsigned int *_hash_shift,
                        unsigned int *_hash_mask,
                        unsigned long low_limit,
                        unsigned long high_limit);

#define HASH_EARLY  0x00000001  /* Allocating during early boot? */
#define HASH_SMALL  0x00000002  /* sub-page allocation allowed, min
                                 * shift passed via *_hash_shift */
#define HASH_ZERO   0x00000004  /* Zero allocated hash table */

extern unsigned long max_low_pfn;
extern unsigned long min_low_pfn;

/*
 * highest page
 */
extern unsigned long max_pfn;

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
    MEMBLOCK_DRIVER_MANAGED = 0x8,  /* always detected via a driver */
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

#define for_each_memblock(memblock_type, region)                    \
    for (region = memblock.memblock_type.regions;                   \
         region < (memblock.memblock_type.regions + memblock.memblock_type.cnt);    \
         region++)

#define for_each_memblock_type(i, memblock_type, rgn)           \
    for (i = 0, rgn = &memblock_type->regions[0];           \
         i < memblock_type->cnt;                    \
         i++, rgn = &memblock_type->regions[i])

/**
 * for_each_mem_range_rev - reverse iterate through memblock areas from
 * type_a and not included in type_b. Or just type_a if type_b is NULL.
 * @i: u64 used as loop variable
 * @type_a: ptr to memblock_type to iterate
 * @type_b: ptr to memblock_type which excludes from the iteration
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 */
#define for_each_mem_range_rev(i, type_a, type_b, nid, flags,   \
                               p_start, p_end, p_nid)           \
    for (i = (u64)ULLONG_MAX,                                   \
         __next_mem_range_rev(&i, nid, flags, type_a, type_b,   \
                              p_start, p_end, p_nid);           \
         i != (u64)ULLONG_MAX;                                  \
         __next_mem_range_rev(&i, nid, flags, type_a, type_b,   \
                              p_start, p_end, p_nid))

/**
 * for_each_free_mem_range_reverse - rev-iterate through free memblock areas
 * @i: u64 used as loop variable
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 *
 * Walks over free (memory && !reserved) areas of memblock in reverse
 * order.  Available as soon as memblock is initialized.
 */
#define for_each_free_mem_range_reverse(i, nid, flags,          \
                                        p_start, p_end, p_nid)  \
    for_each_mem_range_rev(i, &memblock.memory, &memblock.reserved, \
                           nid, flags, p_start, p_end, p_nid)

void memblock_allow_resize(void);
int memblock_remove(phys_addr_t base, phys_addr_t size);
int memblock_add(phys_addr_t base, phys_addr_t size);
int memblock_reserve(phys_addr_t base, phys_addr_t size);

void memblock_dump_all(void);

static inline bool memblock_is_nomap(struct memblock_region *m)
{
    return m->flags & MEMBLOCK_NOMAP;
}

phys_addr_t
memblock_phys_alloc_range(phys_addr_t size, phys_addr_t align,
                          phys_addr_t start, phys_addr_t end);

static inline phys_addr_t
memblock_phys_alloc(phys_addr_t size, phys_addr_t align)
{
    return memblock_phys_alloc_range(size, align, 0, MEMBLOCK_ALLOC_ACCESSIBLE);
}

/*
 * Check if the allocation direction is bottom-up or not.
 * if this is true, that said, memblock will allocate memory
 * in bottom-up direction.
 */
static inline bool memblock_bottom_up(void)
{
    return memblock.bottom_up;
}

static inline int
memblock_get_region_node(const struct memblock_region *r)
{
    return 0;
}

void *memblock_alloc_try_nid(phys_addr_t size, phys_addr_t align,
                             phys_addr_t min_addr, phys_addr_t max_addr,
                             int nid);

static __always_inline void *
memblock_alloc(phys_addr_t size, phys_addr_t align)
{
    return memblock_alloc_try_nid(size, align, MEMBLOCK_LOW_LIMIT,
                                  MEMBLOCK_ALLOC_ACCESSIBLE, NUMA_NO_NODE);
}

void __next_mem_range_rev(u64 *idx, int nid, enum memblock_flags flags,
                          struct memblock_type *type_a,
                          struct memblock_type *type_b,
                          phys_addr_t *out_start, phys_addr_t *out_end,
                          int *out_nid);

phys_addr_t memblock_start_of_DRAM(void);
phys_addr_t memblock_end_of_DRAM(void);

void __next_mem_pfn_range(int *idx, int nid, unsigned long *out_start_pfn,
                          unsigned long *out_end_pfn, int *out_nid);

/**
 * for_each_mem_pfn_range - early memory pfn range iterator
 * @i: an integer used as loop variable
 * @nid: node selector, %MAX_NUMNODES for all nodes
 * @p_start: ptr to ulong for start pfn of the range, can be %NULL
 * @p_end: ptr to ulong for end pfn of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 *
 * Walks over configured memory ranges.
 */
#define for_each_mem_pfn_range(i, nid, p_start, p_end, p_nid)           \
    for (i = -1, __next_mem_pfn_range(&i, nid, p_start, p_end, p_nid);  \
         i >= 0; __next_mem_pfn_range(&i, nid, p_start, p_end, p_nid))

void *
memblock_alloc_exact_nid_raw(phys_addr_t size, phys_addr_t align,
                             phys_addr_t min_addr, phys_addr_t max_addr, int nid);
void *
memblock_alloc_try_nid_raw(phys_addr_t size, phys_addr_t align,
                           phys_addr_t min_addr, phys_addr_t max_addr, int nid);

static inline void *
memblock_alloc_node(phys_addr_t size, phys_addr_t align, int nid)
{
    return memblock_alloc_try_nid(size, align, MEMBLOCK_LOW_LIMIT,
                                  MEMBLOCK_ALLOC_ACCESSIBLE, nid);
}

void memblock_free_all(void);
void memblock_free(void *ptr, size_t size);
void reset_node_managed_pages(pg_data_t *pgdat);
void reset_all_zones_managed_pages(void);

void __next_mem_range(u64 *idx, int nid, enum memblock_flags flags,
                      struct memblock_type *type_a,
                      struct memblock_type *type_b, phys_addr_t *out_start,
                      phys_addr_t *out_end, int *out_nid);

/**
 * __for_each_mem_range - iterate through memblock areas from type_a and not
 * included in type_b. Or just type_a if type_b is NULL.
 * @i: u64 used as loop variable
 * @type_a: ptr to memblock_type to iterate
 * @type_b: ptr to memblock_type which excludes from the iteration
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 */
#define __for_each_mem_range(i, type_a, type_b, nid, flags, \
                             p_start, p_end, p_nid)         \
    for (i = 0, __next_mem_range(&i, nid, flags, type_a, type_b,    \
                                 p_start, p_end, p_nid);            \
         i != (u64)ULLONG_MAX;                                      \
         __next_mem_range(&i, nid, flags, type_a, type_b,           \
                          p_start, p_end, p_nid))

/**
 * for_each_reserved_mem_range - iterate over all reserved memblock areas
 * @i: u64 used as loop variable
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 *
 * Walks over reserved areas of memblock. Available as soon as memblock
 * is initialized.
 */
#define for_each_reserved_mem_range(i, p_start, p_end) \
    __for_each_mem_range(i, &memblock.reserved, NULL, NUMA_NO_NODE, \
                         MEMBLOCK_NONE, p_start, p_end, NULL)

/**
 * for_each_mem_region - itereate over memory regions
 * @region: loop variable
 */
#define for_each_mem_region(region) \
    for (region = memblock.memory.regions; \
         region < (memblock.memory.regions + memblock.memory.cnt); \
         region++)

/**
 * for_each_free_mem_range - iterate through free memblock areas
 * @i: u64 used as loop variable
 * @nid: node selector, %NUMA_NO_NODE for all nodes
 * @flags: pick from blocks based on memory attributes
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 * @p_nid: ptr to int for nid of the range, can be %NULL
 *
 * Walks over free (memory && !reserved) areas of memblock.  Available as
 * soon as memblock is initialized.
 */
#define for_each_free_mem_range(i, nid, flags, p_start, p_end, p_nid) \
    __for_each_mem_range(i, &memblock.memory, &memblock.reserved, \
                         nid, flags, p_start, p_end, p_nid)

static inline void memblock_set_region_node(struct memblock_region *r, int nid)
{
}

void memblock_enforce_memory_limit(phys_addr_t memory_limit);

static inline void *
memblock_alloc_from(phys_addr_t size, phys_addr_t align, phys_addr_t min_addr)
{
    return memblock_alloc_try_nid(size, align, min_addr,
                                  MEMBLOCK_ALLOC_ACCESSIBLE, NUMA_NO_NODE);
}

static inline void *memblock_alloc_low(phys_addr_t size, phys_addr_t align)
{
    return memblock_alloc_try_nid(size, align, MEMBLOCK_LOW_LIMIT,
                                  ARCH_LOW_ADDRESS_LIMIT, NUMA_NO_NODE);
}

bool memblock_is_memory(phys_addr_t addr);

/**
 * for_each_mem_range - iterate through memory areas.
 * @i: u64 used as loop variable
 * @p_start: ptr to phys_addr_t for start address of the range, can be %NULL
 * @p_end: ptr to phys_addr_t for end address of the range, can be %NULL
 */
#define for_each_mem_range(i, p_start, p_end) \
    __for_each_mem_range(i, &memblock.memory, NULL, NUMA_NO_NODE, \
                         MEMBLOCK_HOTPLUG | MEMBLOCK_DRIVER_MANAGED, \
                         p_start, p_end, NULL)

static inline void *memblock_alloc_raw(phys_addr_t size,
                           phys_addr_t align)
{
    return memblock_alloc_try_nid_raw(size, align, MEMBLOCK_LOW_LIMIT,
                                      MEMBLOCK_ALLOC_ACCESSIBLE, NUMA_NO_NODE);
}

/**
 * memblock_region_reserved_base_pfn - get the lowest pfn of the reserved region
 * @reg: memblock_region structure
 *
 * Return: the lowest pfn intersecting with the reserved region
 */
static inline unsigned long
memblock_region_reserved_base_pfn(const struct memblock_region *reg)
{
    return PFN_DOWN(reg->base);
}

/**
 * memblock_region_reserved_end_pfn - get the end pfn of the reserved region
 * @reg: memblock_region structure
 *
 * Return: the end_pfn of the reserved region
 */
static inline unsigned long
memblock_region_reserved_end_pfn(const struct memblock_region *reg)
{
    return PFN_UP(reg->base + reg->size);
}

/**
 * for_each_reserved_mem_region - itereate over reserved memory regions
 * @region: loop variable
 */
#define for_each_reserved_mem_region(region)                \
    for (region = memblock.reserved.regions;            \
         region < (memblock.reserved.regions + memblock.reserved.cnt); \
         region++)

/**
 * memblock_region_memory_base_pfn - get the lowest pfn of the memory region
 * @reg: memblock_region structure
 *
 * Return: the lowest pfn intersecting with the memory region
 */
static inline unsigned long
memblock_region_memory_base_pfn(const struct memblock_region *reg)
{
    return PFN_UP(reg->base);
}

/**
 * memblock_region_memory_end_pfn - get the end pfn of the memory region
 * @reg: memblock_region structure
 *
 * Return: the end_pfn of the reserved region
 */
static inline unsigned long
memblock_region_memory_end_pfn(const struct memblock_region *reg)
{
    return PFN_DOWN(reg->base + reg->size);
}

#endif /* _LINUX_MEMBLOCK_H */

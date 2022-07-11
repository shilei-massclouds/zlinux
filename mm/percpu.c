// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/percpu.c - percpu memory allocator
 *
 * Copyright (C) 2009       SUSE Linux Products GmbH
 * Copyright (C) 2009       Tejun Heo <tj@kernel.org>
 *
 * Copyright (C) 2017       Facebook Inc.
 * Copyright (C) 2017       Dennis Zhou <dennis@kernel.org>
 *
 * The percpu allocator handles both static and dynamic areas.  Percpu
 * areas are allocated in chunks which are divided into units.  There is
 * a 1-to-1 mapping for units to possible cpus.  These units are grouped
 * based on NUMA properties of the machine.
 *
 *  c0                           c1                         c2
 *  -------------------          -------------------        ------------
 * | u0 | u1 | u2 | u3 |        | u0 | u1 | u2 | u3 |      | u0 | u1 | u
 *  -------------------  ......  -------------------  ....  ------------
 *
 * Allocation is done by offsets into a unit's address space.  Ie., an
 * area of 512 bytes at 6k in c1 occupies 512 bytes at 6k in c1:u0,
 * c1:u1, c1:u2, etc.  On NUMA machines, the mapping may be non-linear
 * and even sparse.  Access is handled by configuring percpu base
 * registers according to the cpu to unit mappings and offsetting the
 * base address using pcpu_unit_size.
 *
 * There is special consideration for the first chunk which must handle
 * the static percpu variables in the kernel image as allocation services
 * are not online yet.  In short, the first chunk is structured like so:
 *
 *                  <Static | [Reserved] | Dynamic>
 *
 * The static data is copied from the original section managed by the
 * linker.  The reserved section, if non-zero, primarily manages static
 * percpu variables from kernel modules.  Finally, the dynamic section
 * takes care of normal allocations.
 *
 * The allocator organizes chunks into lists according to free size and
 * memcg-awareness.  To make a percpu allocation memcg-aware the __GFP_ACCOUNT
 * flag should be passed.  All memcg-aware allocations are sharing one set
 * of chunks and all unaccounted allocations and allocations performed
 * by processes belonging to the root memory cgroup are using the second set.
 *
 * The allocator tries to allocate from the fullest chunk first. Each chunk
 * is managed by a bitmap with metadata blocks.  The allocation map is updated
 * on every allocation and free to reflect the current state while the boundary
 * map is only updated on allocation.  Each metadata block contains
 * information to help mitigate the need to iterate over large portions
 * of the bitmap.  The reverse mapping from page to chunk is stored in
 * the page's index.  Lastly, units are lazily backed and grow in unison.
 *
 * There is a unique conversion that goes on here between bytes and bits.
 * Each bit represents a fragment of size PCPU_MIN_ALLOC_SIZE.  The chunk
 * tracks the number of pages it is responsible for in nr_pages.  Helper
 * functions are used to convert from between the bytes, bits, and blocks.
 * All hints are managed in bits unless explicitly stated.
 *
 * To use this allocator, arch code should do the following:
 *
 * - define __addr_to_pcpu_ptr() and __pcpu_ptr_to_addr() to translate
 *   regular address to percpu pointer and back if they need to be
 *   different from the default
 *
 * - use pcpu_setup_first_chunk() during percpu area initialization to
 *   setup the first chunk containing the kernel static percpu area
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/bitmap.h>
#include <linux/memblock.h>
#include <linux/err.h>
#include <linux/lcm.h>
#include <linux/list.h>
#include <linux/log2.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/pfn.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
//#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/memcontrol.h>
#include <linux/math.h>

#if 0
#include <asm/cacheflush.h>
#endif
#include <asm/sections.h>
#include <asm/tlbflush.h>
#include <asm/io.h>

#include "percpu-internal.h"

/*
 * The slots are sorted by the size of the biggest continuous free area.
 * 1-31 bytes share the same slot.
 */
#define PCPU_SLOT_BASE_SHIFT        5
/* chunks in slots below this are subject to being sidelined on failed alloc */
#define PCPU_SLOT_FAIL_THRESHOLD    3

#define PCPU_EMPTY_POP_PAGES_HIGH   4

/* default addr <-> pcpu_ptr mapping, override in asm/percpu.h if necessary */
#ifndef __addr_to_pcpu_ptr
#define __addr_to_pcpu_ptr(addr) \
    (void __percpu *)((unsigned long)(addr) - \
                      (unsigned long)pcpu_base_addr + \
                      (unsigned long)__per_cpu_start)
#endif

#ifndef __pcpu_ptr_to_addr
#define __pcpu_ptr_to_addr(ptr) \
    (void __force *)((unsigned long)(ptr) + \
                     (unsigned long)pcpu_base_addr - \
                     (unsigned long)__per_cpu_start)
#endif

/* the address of the first chunk which starts with the kernel static area */
void *pcpu_base_addr __ro_after_init;

/*
 * The first chunk which always exists.  Note that unlike other
 * chunks, this one can be allocated and mapped in several different
 * ways and thus often doesn't live in the vmalloc area.
 */
struct pcpu_chunk *pcpu_first_chunk __ro_after_init;

/*
 * The number of empty populated pages, protected by pcpu_lock.
 * The reserved chunk doesn't contribute to the count.
 */
int pcpu_nr_empty_pop_pages;

/*
 * The number of populated pages in use by the allocator, protected by
 * pcpu_lock.  This number is kept per a unit per chunk (i.e. when a page gets
 * allocated/deallocated, it is allocated/deallocated in all units of a chunk
 * and increments/decrements this count by 1).
 */
static unsigned long pcpu_nr_populated;

/*
 * Generic SMP percpu area setup.
 *
 * The embedding helper is used because its behavior closely resembles
 * the original non-dynamic generic percpu area setup.  This is
 * important because many archs have addressing restrictions and might
 * fail if the percpu area is located far away from the previous
 * location.  As an added bonus, in non-NUMA cases, embedding is
 * generally a good idea TLB-wise because percpu area can piggy back
 * on the physical linear memory mapping which uses large page
 * mappings on applicable archs.
 */
unsigned long __per_cpu_offset[NR_CPUS] __read_mostly;
EXPORT_SYMBOL(__per_cpu_offset);

struct list_head *pcpu_chunk_lists __ro_after_init; /* chunk list slots */

/*
 * Optional reserved chunk.  This chunk reserves part of the first
 * chunk and serves it for reserved allocations.  When the reserved
 * region doesn't exist, the following variable is NULL.
 */
struct pcpu_chunk *pcpu_reserved_chunk __ro_after_init;

DEFINE_SPINLOCK(pcpu_lock); /* all internal data structures */
/* chunk create/destroy, [de]pop, map ext */
static DEFINE_MUTEX(pcpu_alloc_mutex);

static int pcpu_nr_units __ro_after_init;
static int pcpu_unit_pages __ro_after_init;
static int pcpu_unit_size __ro_after_init;
static int pcpu_atom_size __ro_after_init;
int pcpu_nr_slots __ro_after_init;
static int pcpu_free_slot __ro_after_init;
int pcpu_sidelined_slot __ro_after_init;
int pcpu_to_depopulate_slot __ro_after_init;
static size_t pcpu_chunk_struct_size __ro_after_init;

static const int *pcpu_unit_map __ro_after_init;        /* cpu -> unit */
const unsigned long *pcpu_unit_offsets __ro_after_init; /* cpu -> unit offset */

/* group information, used for vm allocation */
static int pcpu_nr_groups __ro_after_init;
static const unsigned long *pcpu_group_offsets __ro_after_init;
static const size_t *pcpu_group_sizes __ro_after_init;

/* cpus with the lowest and highest unit addresses */
static unsigned int pcpu_low_unit_cpu __ro_after_init;
static unsigned int pcpu_high_unit_cpu __ro_after_init;

#include "percpu-vm.c"

static unsigned long pcpu_unit_page_offset(unsigned int cpu, int page_idx)
{
    return pcpu_unit_offsets[cpu] + (page_idx << PAGE_SHIFT);
}

static unsigned long
pcpu_chunk_addr(struct pcpu_chunk *chunk, unsigned int cpu, int page_idx)
{
    return (unsigned long)chunk->base_addr +
        pcpu_unit_page_offset(cpu, page_idx);
}

/*
 * The following are helper functions to help access bitmaps and convert
 * between bitmap offsets to address offsets.
 */
static unsigned long *pcpu_index_alloc_map(struct pcpu_chunk *chunk, int index)
{
    return chunk->alloc_map +
           (index * PCPU_BITMAP_BLOCK_BITS / BITS_PER_LONG);
}

static unsigned long pcpu_off_to_block_index(int off)
{
    return off / PCPU_BITMAP_BLOCK_BITS;
}

static unsigned long pcpu_off_to_block_off(int off)
{
    return off & (PCPU_BITMAP_BLOCK_BITS - 1);
}

static unsigned long pcpu_block_off_to_off(int index, int off)
{
    return index * PCPU_BITMAP_BLOCK_BITS + off;
}

/*
 * pcpu_next_hint - determine which hint to use
 * @block: block of interest
 * @alloc_bits: size of allocation
 *
 * This determines if we should scan based on the scan_hint or first_free.
 * In general, we want to scan from first_free to fulfill allocations by
 * first fit.  However, if we know a scan_hint at position scan_hint_start
 * cannot fulfill an allocation, we can begin scanning from there knowing
 * the contig_hint will be our fallback.
 */
static int pcpu_next_hint(struct pcpu_block_md *block, int alloc_bits)
{
    /*
     * The three conditions below determine if we can skip past the
     * scan_hint.  First, does the scan hint exist.  Second, is the
     * contig_hint after the scan_hint (possibly not true iff
     * contig_hint == scan_hint).  Third, is the allocation request
     * larger than the scan_hint.
     */
    if (block->scan_hint && block->contig_hint_start > block->scan_hint_start &&
        alloc_bits > block->scan_hint)
        return block->scan_hint_start + block->scan_hint;

    return block->first_free;
}

/**
 * pcpu_next_fit_region - finds fit areas for a given allocation request
 * @chunk: chunk of interest
 * @alloc_bits: size of allocation
 * @align: alignment of area (max PAGE_SIZE)
 * @bit_off: chunk offset
 * @bits: size of free area
 *
 * Finds the next free region that is viable for use with a given size and
 * alignment.  This only returns if there is a valid area to be used for this
 * allocation.  block->first_free is returned if the allocation request fits
 * within the block to see if the request can be fulfilled prior to the contig
 * hint.
 */
static void
pcpu_next_fit_region(struct pcpu_chunk *chunk, int alloc_bits,
                     int align, int *bit_off, int *bits)
{
    struct pcpu_block_md *block;
    int i = pcpu_off_to_block_index(*bit_off);
    int block_off = pcpu_off_to_block_off(*bit_off);

    *bits = 0;
    for (block = chunk->md_blocks + i; i < pcpu_chunk_nr_blocks(chunk);
         block++, i++) {
        /* handles contig area across blocks */
        if (*bits) {
            *bits += block->left_free;
            if (*bits >= alloc_bits)
                return;
            if (block->left_free == PCPU_BITMAP_BLOCK_BITS)
                continue;
        }

        /* check block->contig_hint */
        *bits = ALIGN(block->contig_hint_start, align) -
            block->contig_hint_start;
        /*
         * This uses the block offset to determine if this has been
         * checked in the prior iteration.
         */
        if (block->contig_hint &&
            block->contig_hint_start >= block_off &&
            block->contig_hint >= *bits + alloc_bits) {
            int start = pcpu_next_hint(block, alloc_bits);

            *bits += alloc_bits + block->contig_hint_start - start;
            *bit_off = pcpu_block_off_to_off(i, start);
            return;
        }
        /* reset to satisfy the second predicate above */
        block_off = 0;

        *bit_off = ALIGN(PCPU_BITMAP_BLOCK_BITS - block->right_free, align);
        *bits = PCPU_BITMAP_BLOCK_BITS - *bit_off;
        *bit_off = pcpu_block_off_to_off(i, *bit_off);
        if (*bits >= alloc_bits)
            return;
    }

    /* no valid offsets were found - fail condition */
    *bit_off = pcpu_chunk_map_bits(chunk);
}

/*
 * Metadata free area iterators.  These perform aggregation of free areas
 * based on the metadata blocks and return the offset @bit_off and size in
 * bits of the free area @bits.  pcpu_for_each_fit_region only returns when
 * a fit is found for the allocation request.
 */
#define pcpu_for_each_md_free_region(chunk, bit_off, bits)      \
    for (pcpu_next_md_free_region((chunk), &(bit_off), &(bits));    \
         (bit_off) < pcpu_chunk_map_bits((chunk));          \
         (bit_off) += (bits) + 1,                   \
         pcpu_next_md_free_region((chunk), &(bit_off), &(bits)))

#define pcpu_for_each_fit_region(chunk, alloc_bits, align, bit_off, bits)     \
    for (pcpu_next_fit_region((chunk), (alloc_bits), (align), &(bit_off), \
                  &(bits));                   \
         (bit_off) < pcpu_chunk_map_bits((chunk));                \
         (bit_off) += (bits),                         \
         pcpu_next_fit_region((chunk), (alloc_bits), (align), &(bit_off), \
                  &(bits)))

/**
 * pcpu_next_md_free_region - finds the next hint free area
 * @chunk: chunk of interest
 * @bit_off: chunk offset
 * @bits: size of free area
 *
 * Helper function for pcpu_for_each_md_free_region.  It checks
 * block->contig_hint and performs aggregation across blocks to find the
 * next hint.  It modifies bit_off and bits in-place to be consumed in the
 * loop.
 */
static void
pcpu_next_md_free_region(struct pcpu_chunk *chunk, int *bit_off, int *bits)
{
    int i = pcpu_off_to_block_index(*bit_off);
    int block_off = pcpu_off_to_block_off(*bit_off);
    struct pcpu_block_md *block;

    *bits = 0;

    for (block = chunk->md_blocks + i; i < pcpu_chunk_nr_blocks(chunk);
         block++, i++) {
        /* handles contig area across blocks */
        if (*bits) {
            *bits += block->left_free;
            if (block->left_free == PCPU_BITMAP_BLOCK_BITS)
                continue;
            return;
        }

        /*
         * This checks three things.  First is there a contig_hint to
         * check.  Second, have we checked this hint before by
         * comparing the block_off.  Third, is this the same as the
         * right contig hint.  In the last case, it spills over into
         * the next block and should be handled by the contig area
         * across blocks code.
         */
        *bits = block->contig_hint;
        if (*bits && block->contig_hint_start >= block_off &&
            *bits + block->contig_hint_start < PCPU_BITMAP_BLOCK_BITS) {
            *bit_off = pcpu_block_off_to_off(i, block->contig_hint_start);
            return;
        }
        /* reset to satisfy the second predicate above */
        block_off = 0;

        *bits = block->right_free;
        *bit_off = (i + 1) * PCPU_BITMAP_BLOCK_BITS - block->right_free;
    }
}

/**
 * pcpu_alloc_alloc_info - allocate percpu allocation info
 * @nr_groups: the number of groups
 * @nr_units: the number of units
 *
 * Allocate ai which is large enough for @nr_groups groups containing
 * @nr_units units.  The returned ai's groups[0].cpu_map points to the
 * cpu_map array which is long enough for @nr_units and filled with
 * NR_CPUS.  It's the caller's responsibility to initialize cpu_map
 * pointer of other groups.
 *
 * RETURNS:
 * Pointer to the allocated pcpu_alloc_info on success, NULL on
 * failure.
 */
struct pcpu_alloc_info * __init
pcpu_alloc_alloc_info(int nr_groups, int nr_units)
{
    int unit;
    void *ptr;
    size_t base_size, ai_size;
    struct pcpu_alloc_info *ai;

    base_size = ALIGN(struct_size(ai, groups, nr_groups),
                      __alignof__(ai->groups[0].cpu_map[0]));
    ai_size = base_size + nr_units * sizeof(ai->groups[0].cpu_map[0]);

    ptr = memblock_alloc(PFN_ALIGN(ai_size), PAGE_SIZE);
    if (!ptr)
        return NULL;
    ai = ptr;
    ptr += base_size;

    ai->groups[0].cpu_map = ptr;

    for (unit = 0; unit < nr_units; unit++)
        ai->groups[0].cpu_map[unit] = NR_CPUS;

    ai->nr_groups = nr_groups;
    ai->__ai_size = PFN_ALIGN(ai_size);

    return ai;
}

/**
 * pcpu_build_alloc_info - build alloc_info considering distances between CPUs
 * @reserved_size: the size of reserved percpu area in bytes
 * @dyn_size: minimum free size for dynamic allocation in bytes
 * @atom_size: allocation atom size
 * @cpu_distance_fn: callback to determine distance between cpus, optional
 *
 * This function determines grouping of units, their mappings to cpus
 * and other parameters considering needed percpu size, allocation
 * atom size and distances between CPUs.
 *
 * Groups are always multiples of atom size and CPUs which are of
 * LOCAL_DISTANCE both ways are grouped together and share space for
 * units in the same group.  The returned configuration is guaranteed
 * to have CPUs on different nodes on different groups and >=75% usage
 * of allocated virtual address space.
 *
 * RETURNS:
 * On success, pointer to the new allocation_info is returned.  On
 * failure, ERR_PTR value is returned.
 */
static struct pcpu_alloc_info * __init __flatten
pcpu_build_alloc_info(size_t reserved_size, size_t dyn_size,
                      size_t atom_size,
                      pcpu_fc_cpu_distance_fn_t cpu_distance_fn)
{
    static int group_map[NR_CPUS] __initdata;
    static int group_cnt[NR_CPUS] __initdata;
    static struct cpumask mask __initdata;
    const size_t static_size = __per_cpu_end - __per_cpu_start;
    int nr_groups = 1, nr_units = 0;
    size_t size_sum, min_unit_size, alloc_size;
    int upa, max_upa, best_upa; /* units_per_alloc */
    int last_allocs, group, unit;
    unsigned int cpu, tcpu;
    struct pcpu_alloc_info *ai;
    unsigned int *cpu_map;

    /* this function may be called multiple times */
    memset(group_map, 0, sizeof(group_map));
    memset(group_cnt, 0, sizeof(group_cnt));
    cpumask_clear(&mask);

    /* calculate size_sum and ensure dyn_size is enough for early alloc */
    size_sum = PFN_ALIGN(static_size + reserved_size +
                         max_t(size_t, dyn_size, PERCPU_DYNAMIC_EARLY_SIZE));
    dyn_size = size_sum - static_size - reserved_size;

    /*
     * Determine min_unit_size, alloc_size and max_upa such that
     * alloc_size is multiple of atom_size and is the smallest
     * which can accommodate 4k aligned segments which are equal to
     * or larger than min_unit_size.
     */
    min_unit_size = max_t(size_t, size_sum, PCPU_MIN_UNIT_SIZE);

    /* determine the maximum # of units that can fit in an allocation */
    alloc_size = roundup(min_unit_size, atom_size);
    upa = alloc_size / min_unit_size;
    while (alloc_size % upa || (offset_in_page(alloc_size / upa)))
        upa--;
    max_upa = upa;

    cpumask_copy(&mask, cpu_possible_mask);

    /* group cpus according to their proximity */
    for (group = 0; !cpumask_empty(&mask); group++) {
        /* pop the group's first cpu */
        cpu = cpumask_first(&mask);
        group_map[cpu] = group;
        group_cnt[group]++;
        cpumask_clear_cpu(cpu, &mask);

        for_each_cpu(tcpu, &mask) {
            if (!cpu_distance_fn ||
                (cpu_distance_fn(cpu, tcpu) == LOCAL_DISTANCE &&
                 cpu_distance_fn(tcpu, cpu) == LOCAL_DISTANCE)) {
                group_map[tcpu] = group;
                group_cnt[group]++;
                cpumask_clear_cpu(tcpu, &mask);
            }
        }
    }
    nr_groups = group;

    /*
     * Wasted space is caused by a ratio imbalance of upa to group_cnt.
     * Expand the unit_size until we use >= 75% of the units allocated.
     * Related to atom_size, which could be much larger than the unit_size.
     */
    last_allocs = INT_MAX;
    best_upa = 0;
    for (upa = max_upa; upa; upa--) {
        int allocs = 0, wasted = 0;

        if (alloc_size % upa || (offset_in_page(alloc_size / upa)))
            continue;

        for (group = 0; group < nr_groups; group++) {
            int this_allocs = DIV_ROUND_UP(group_cnt[group], upa);
            allocs += this_allocs;
            wasted += this_allocs * upa - group_cnt[group];
        }

        /*
         * Don't accept if wastage is over 1/3.  The
         * greater-than comparison ensures upa==1 always
         * passes the following check.
         */
        if (wasted > num_possible_cpus() / 3)
            continue;

        /* and then don't consume more memory */
        if (allocs > last_allocs)
            break;
        last_allocs = allocs;
        best_upa = upa;
    }
    BUG_ON(!best_upa);
    upa = best_upa;

    /* allocate and fill alloc_info */
    for (group = 0; group < nr_groups; group++)
        nr_units += roundup(group_cnt[group], upa);

    ai = pcpu_alloc_alloc_info(nr_groups, nr_units);
    if (!ai)
        return ERR_PTR(-ENOMEM);
    cpu_map = ai->groups[0].cpu_map;

    for (group = 0; group < nr_groups; group++) {
        ai->groups[group].cpu_map = cpu_map;
        cpu_map += roundup(group_cnt[group], upa);
    }

    ai->static_size = static_size;
    ai->reserved_size = reserved_size;
    ai->dyn_size = dyn_size;
    ai->unit_size = alloc_size / upa;
    ai->atom_size = atom_size;
    ai->alloc_size = alloc_size;

    for (group = 0, unit = 0; group < nr_groups; group++) {
        struct pcpu_group_info *gi = &ai->groups[group];

        /*
         * Initialize base_offset as if all groups are located
         * back-to-back.  The caller should update this to
         * reflect actual allocation.
         */
        gi->base_offset = unit * ai->unit_size;

        for_each_possible_cpu(cpu)
            if (group_map[cpu] == group)
                gi->cpu_map[gi->nr_units++] = cpu;
        gi->nr_units = roundup(gi->nr_units, upa);
        unit += gi->nr_units;
    }
    BUG_ON(unit != nr_units);
    return ai;
}

/**
 * pcpu_free_alloc_info - free percpu allocation info
 * @ai: pcpu_alloc_info to free
 *
 * Free @ai which was allocated by pcpu_alloc_alloc_info().
 */
void __init pcpu_free_alloc_info(struct pcpu_alloc_info *ai)
{
    memblock_free(ai, ai->__ai_size);
}

/**
 * pcpu_dump_alloc_info - print out information about pcpu_alloc_info
 * @lvl: loglevel
 * @ai: allocation info to dump
 *
 * Print out information about @ai using loglevel @lvl.
 */
static void
pcpu_dump_alloc_info(const char *lvl, const struct pcpu_alloc_info *ai)
{
}

static int __pcpu_size_to_slot(int size)
{
    int highbit = fls(size);    /* size is in bytes */
    return max(highbit - PCPU_SLOT_BASE_SHIFT + 2, 1);
}

static void pcpu_init_md_block(struct pcpu_block_md *block, int nr_bits)
{
    block->scan_hint = 0;
    block->contig_hint = nr_bits;
    block->left_free = nr_bits;
    block->right_free = nr_bits;
    block->first_free = 0;
    block->nr_bits = nr_bits;
}

static void pcpu_init_md_blocks(struct pcpu_chunk *chunk)
{
    struct pcpu_block_md *md_block;

    /* init the chunk's block */
    pcpu_init_md_block(&chunk->chunk_md, pcpu_chunk_map_bits(chunk));

    for (md_block = chunk->md_blocks;
         md_block != chunk->md_blocks + pcpu_chunk_nr_blocks(chunk);
         md_block++)
        pcpu_init_md_block(md_block, PCPU_BITMAP_BLOCK_BITS);
}

/*
 * pcpu_region_overlap - determines if two regions overlap
 * @a: start of first region, inclusive
 * @b: end of first region, exclusive
 * @x: start of second region, inclusive
 * @y: end of second region, exclusive
 *
 * This is used to determine if the hint region [a, b) overlaps with the
 * allocated region [x, y).
 */
static inline bool pcpu_region_overlap(int a, int b, int x, int y)
{
    return (a < y) && (x < b);
}

/**
 * pcpu_block_update - updates a block given a free area
 * @block: block of interest
 * @start: start offset in block
 * @end: end offset in block
 *
 * Updates a block given a known free area.  The region [start, end) is
 * expected to be the entirety of the free area within a block.  Chooses
 * the best starting offset if the contig hints are equal.
 */
static void pcpu_block_update(struct pcpu_block_md *block, int start, int end)
{
    int contig = end - start;

    block->first_free = min(block->first_free, start);
    if (start == 0)
        block->left_free = contig;

    if (end == block->nr_bits)
        block->right_free = contig;

    if (contig > block->contig_hint) {
        /* promote the old contig_hint to be the new scan_hint */
        if (start > block->contig_hint_start) {
            if (block->contig_hint > block->scan_hint) {
                block->scan_hint_start = block->contig_hint_start;
                block->scan_hint = block->contig_hint;
            } else if (start < block->scan_hint_start) {
                /*
                 * The old contig_hint == scan_hint.  But, the
                 * new contig is larger so hold the invariant
                 * scan_hint_start < contig_hint_start.
                 */
                block->scan_hint = 0;
            }
        } else {
            block->scan_hint = 0;
        }
        block->contig_hint_start = start;
        block->contig_hint = contig;
    } else if (contig == block->contig_hint) {
        if (block->contig_hint_start &&
            (!start || __ffs(start) > __ffs(block->contig_hint_start))) {
            /* start has a better alignment so use it */
            block->contig_hint_start = start;
            if (start < block->scan_hint_start &&
                block->contig_hint > block->scan_hint)
                block->scan_hint = 0;
        } else if (start > block->scan_hint_start ||
                   block->contig_hint > block->scan_hint) {
            /*
             * Knowing contig == contig_hint, update the scan_hint
             * if it is farther than or larger than the current
             * scan_hint.
             */
            block->scan_hint_start = start;
            block->scan_hint = contig;
        }
    } else {
        /*
         * The region is smaller than the contig_hint.  So only update
         * the scan_hint if it is larger than or equal and farther than
         * the current scan_hint.
         */
        if ((start < block->contig_hint_start &&
             (contig > block->scan_hint ||
              (contig == block->scan_hint &&
               start > block->scan_hint_start)))) {
            block->scan_hint_start = start;
            block->scan_hint = contig;
        }
    }
}

/**
 * pcpu_block_refresh_hint
 * @chunk: chunk of interest
 * @index: index of the metadata block
 *
 * Scans over the block beginning at first_free and updates the block
 * metadata accordingly.
 */
static void pcpu_block_refresh_hint(struct pcpu_chunk *chunk, int index)
{
    struct pcpu_block_md *block = chunk->md_blocks + index;
    unsigned long *alloc_map = pcpu_index_alloc_map(chunk, index);
    unsigned int rs, re, start; /* region start, region end */

    /* promote scan_hint to contig_hint */
    if (block->scan_hint) {
        start = block->scan_hint_start + block->scan_hint;
        block->contig_hint_start = block->scan_hint_start;
        block->contig_hint = block->scan_hint;
        block->scan_hint = 0;
    } else {
        start = block->first_free;
        block->contig_hint = 0;
    }

    block->right_free = 0;

    /* iterate over free areas and update the contig hints */
    bitmap_for_each_clear_region(alloc_map, rs, re, start,
                                 PCPU_BITMAP_BLOCK_BITS)
        pcpu_block_update(block, rs, re);
}

/*
 * pcpu_update_empty_pages - update empty page counters
 * @chunk: chunk of interest
 * @nr: nr of empty pages
 *
 * This is used to keep track of the empty pages now based on the premise
 * a md_block covers a page.  The hint update functions recognize if a block
 * is made full or broken to calculate deltas for keeping track of free pages.
 */
static inline void pcpu_update_empty_pages(struct pcpu_chunk *chunk, int nr)
{
    chunk->nr_empty_pop_pages += nr;
    if (chunk != pcpu_reserved_chunk && !chunk->isolated)
        pcpu_nr_empty_pop_pages += nr;
}

/**
 * pcpu_chunk_refresh_hint - updates metadata about a chunk
 * @chunk: chunk of interest
 * @full_scan: if we should scan from the beginning
 *
 * Iterates over the metadata blocks to find the largest contig area.
 * A full scan can be avoided on the allocation path as this is triggered
 * if we broke the contig_hint.  In doing so, the scan_hint will be before
 * the contig_hint or after if the scan_hint == contig_hint.  This cannot
 * be prevented on freeing as we want to find the largest area possibly
 * spanning blocks.
 */
static void pcpu_chunk_refresh_hint(struct pcpu_chunk *chunk, bool full_scan)
{
    struct pcpu_block_md *chunk_md = &chunk->chunk_md;
    int bit_off, bits;

    /* promote scan_hint to contig_hint */
    if (!full_scan && chunk_md->scan_hint) {
        bit_off = chunk_md->scan_hint_start + chunk_md->scan_hint;
        chunk_md->contig_hint_start = chunk_md->scan_hint_start;
        chunk_md->contig_hint = chunk_md->scan_hint;
        chunk_md->scan_hint = 0;
    } else {
        bit_off = chunk_md->first_free;
        chunk_md->contig_hint = 0;
    }

    bits = 0;
    pcpu_for_each_md_free_region(chunk, bit_off, bits)
        pcpu_block_update(chunk_md, bit_off, bit_off + bits);
}

/**
 * pcpu_block_update_hint_alloc - update hint on allocation path
 * @chunk: chunk of interest
 * @bit_off: chunk offset
 * @bits: size of request
 *
 * Updates metadata for the allocation path.  The metadata only has to be
 * refreshed by a full scan iff the chunk's contig hint is broken.  Block level
 * scans are required if the block's contig hint is broken.
 */
static void
pcpu_block_update_hint_alloc(struct pcpu_chunk *chunk, int bit_off, int bits)
{
    int s_off, e_off;       /* block offsets of the freed allocation */
    int s_index, e_index;   /* block indexes of the freed allocation */
    int nr_empty_pages = 0;
    struct pcpu_block_md *s_block, *e_block, *block;
    struct pcpu_block_md *chunk_md = &chunk->chunk_md;

    /*
     * Calculate per block offsets.
     * The calculation uses an inclusive range, but the resulting offsets
     * are [start, end).  e_index always points to the last block in the
     * range.
     */
    s_index = pcpu_off_to_block_index(bit_off);
    e_index = pcpu_off_to_block_index(bit_off + bits - 1);
    s_off = pcpu_off_to_block_off(bit_off);
    e_off = pcpu_off_to_block_off(bit_off + bits - 1) + 1;

    s_block = chunk->md_blocks + s_index;
    e_block = chunk->md_blocks + e_index;

    /*
     * Update s_block.
     * block->first_free must be updated if the allocation takes its place.
     * If the allocation breaks the contig_hint, a scan is required to
     * restore this hint.
     */
    if (s_block->contig_hint == PCPU_BITMAP_BLOCK_BITS)
        nr_empty_pages++;

    if (s_off == s_block->first_free)
        s_block->first_free = find_next_zero_bit(
                    pcpu_index_alloc_map(chunk, s_index),
                    PCPU_BITMAP_BLOCK_BITS,
                    s_off + bits);

    if (pcpu_region_overlap(s_block->scan_hint_start,
                            s_block->scan_hint_start + s_block->scan_hint,
                            s_off,
                            s_off + bits))
        s_block->scan_hint = 0;

    if (pcpu_region_overlap(s_block->contig_hint_start,
                            s_block->contig_hint_start + s_block->contig_hint,
                            s_off,
                            s_off + bits)) {
        /* block contig hint is broken - scan to fix it */
        if (!s_off)
            s_block->left_free = 0;
        pcpu_block_refresh_hint(chunk, s_index);
    } else {
        /* update left and right contig manually */
        s_block->left_free = min(s_block->left_free, s_off);
        if (s_index == e_index)
            s_block->right_free = min_t(int, s_block->right_free,
                    PCPU_BITMAP_BLOCK_BITS - e_off);
        else
            s_block->right_free = 0;
    }

    /*
     * Update e_block.
     */
    if (s_index != e_index) {
        if (e_block->contig_hint == PCPU_BITMAP_BLOCK_BITS)
            nr_empty_pages++;

        /*
         * When the allocation is across blocks, the end is along
         * the left part of the e_block.
         */
        e_block->first_free = find_next_zero_bit(
                pcpu_index_alloc_map(chunk, e_index),
                PCPU_BITMAP_BLOCK_BITS, e_off);

        if (e_off == PCPU_BITMAP_BLOCK_BITS) {
            /* reset the block */
            e_block++;
        } else {
            if (e_off > e_block->scan_hint_start)
                e_block->scan_hint = 0;

            e_block->left_free = 0;
            if (e_off > e_block->contig_hint_start) {
                /* contig hint is broken - scan to fix it */
                pcpu_block_refresh_hint(chunk, e_index);
            } else {
                e_block->right_free =
                    min_t(int, e_block->right_free,
                          PCPU_BITMAP_BLOCK_BITS - e_off);
            }
        }

        /* update in-between md_blocks */
        nr_empty_pages += (e_index - s_index - 1);
        for (block = s_block + 1; block < e_block; block++) {
            block->scan_hint = 0;
            block->contig_hint = 0;
            block->left_free = 0;
            block->right_free = 0;
        }
    }

    if (nr_empty_pages)
        pcpu_update_empty_pages(chunk, -nr_empty_pages);

    if (pcpu_region_overlap(chunk_md->scan_hint_start,
                            chunk_md->scan_hint_start + chunk_md->scan_hint,
                            bit_off,
                            bit_off + bits))
        chunk_md->scan_hint = 0;

    /*
     * The only time a full chunk scan is required is if the chunk
     * contig hint is broken.  Otherwise, it means a smaller space
     * was used and therefore the chunk contig hint is still correct.
     */
    if (pcpu_region_overlap(chunk_md->contig_hint_start,
                            chunk_md->contig_hint_start + chunk_md->contig_hint,
                            bit_off,
                            bit_off + bits))
        pcpu_chunk_refresh_hint(chunk, false);
}

/**
 * pcpu_alloc_first_chunk - creates chunks that serve the first chunk
 * @tmp_addr: the start of the region served
 * @map_size: size of the region served
 *
 * This is responsible for creating the chunks that serve the first chunk.  The
 * base_addr is page aligned down of @tmp_addr while the region end is page
 * aligned up.  Offsets are kept track of to determine the region served. All
 * this is done to appease the bitmap allocator in avoiding partial blocks.
 *
 * RETURNS:
 * Chunk serving the region at @tmp_addr of @map_size.
 */
static struct pcpu_chunk * __init
pcpu_alloc_first_chunk(unsigned long tmp_addr, int map_size)
{
    size_t alloc_size;
    struct pcpu_chunk *chunk;
    unsigned long aligned_addr, lcm_align;
    int start_offset, offset_bits, region_size, region_bits;

    /* region calculations */
    aligned_addr = tmp_addr & PAGE_MASK;

    start_offset = tmp_addr - aligned_addr;

    /*
     * Align the end of the region with the LCM of PAGE_SIZE and
     * PCPU_BITMAP_BLOCK_SIZE.  One of these constants is a multiple of
     * the other.
     */
    lcm_align = lcm(PAGE_SIZE, PCPU_BITMAP_BLOCK_SIZE);
    region_size = ALIGN(start_offset + map_size, lcm_align);

    /* allocate chunk */
    alloc_size = struct_size(chunk, populated,
                             BITS_TO_LONGS(region_size >> PAGE_SHIFT));
    chunk = memblock_alloc(alloc_size, SMP_CACHE_BYTES);
    if (!chunk)
        panic("%s: Failed to allocate %zu bytes\n", __func__, alloc_size);

    INIT_LIST_HEAD(&chunk->list);

    chunk->base_addr = (void *)aligned_addr;
    chunk->start_offset = start_offset;
    chunk->end_offset = region_size - chunk->start_offset - map_size;

    chunk->nr_pages = region_size >> PAGE_SHIFT;
    region_bits = pcpu_chunk_map_bits(chunk);

    alloc_size = BITS_TO_LONGS(region_bits) * sizeof(chunk->alloc_map[0]);
    chunk->alloc_map = memblock_alloc(alloc_size, SMP_CACHE_BYTES);
    if (!chunk->alloc_map)
        panic("%s: Failed to allocate %zu bytes\n", __func__, alloc_size);

    alloc_size = BITS_TO_LONGS(region_bits + 1) * sizeof(chunk->bound_map[0]);
    chunk->bound_map = memblock_alloc(alloc_size, SMP_CACHE_BYTES);
    if (!chunk->bound_map)
        panic("%s: Failed to allocate %zu bytes\n", __func__, alloc_size);

    alloc_size = pcpu_chunk_nr_blocks(chunk) * sizeof(chunk->md_blocks[0]);
    chunk->md_blocks = memblock_alloc(alloc_size, SMP_CACHE_BYTES);
    if (!chunk->md_blocks)
        panic("%s: Failed to allocate %zu bytes\n", __func__, alloc_size);

    pcpu_init_md_blocks(chunk);

    /* manage populated page bitmap */
    chunk->immutable = true;
    bitmap_fill(chunk->populated, chunk->nr_pages);
    chunk->nr_populated = chunk->nr_pages;
    chunk->nr_empty_pop_pages = chunk->nr_pages;

    chunk->free_bytes = map_size;

    if (chunk->start_offset) {
        /* hide the beginning of the bitmap */
        offset_bits = chunk->start_offset / PCPU_MIN_ALLOC_SIZE;
        bitmap_set(chunk->alloc_map, 0, offset_bits);
        set_bit(0, chunk->bound_map);
        set_bit(offset_bits, chunk->bound_map);

        chunk->chunk_md.first_free = offset_bits;

        pcpu_block_update_hint_alloc(chunk, 0, offset_bits);
    }

    if (chunk->end_offset) {
        /* hide the end of the bitmap */
        offset_bits = chunk->end_offset / PCPU_MIN_ALLOC_SIZE;
        bitmap_set(chunk->alloc_map,
                   pcpu_chunk_map_bits(chunk) - offset_bits, offset_bits);
        set_bit((start_offset + map_size) / PCPU_MIN_ALLOC_SIZE,
                chunk->bound_map);
        set_bit(region_bits, chunk->bound_map);

        pcpu_block_update_hint_alloc(chunk, pcpu_chunk_map_bits(chunk)
                                     - offset_bits, offset_bits);
    }

    return chunk;
}

static int pcpu_size_to_slot(int size)
{
    if (size == pcpu_unit_size)
        return pcpu_free_slot;
    return __pcpu_size_to_slot(size);
}

static int pcpu_chunk_slot(const struct pcpu_chunk *chunk)
{
    const struct pcpu_block_md *chunk_md = &chunk->chunk_md;

    if (chunk->free_bytes < PCPU_MIN_ALLOC_SIZE || chunk_md->contig_hint == 0)
        return 0;

    return pcpu_size_to_slot(chunk_md->contig_hint * PCPU_MIN_ALLOC_SIZE);
}

static void
__pcpu_chunk_move(struct pcpu_chunk *chunk, int slot, bool move_front)
{
    if (chunk != pcpu_reserved_chunk) {
        if (move_front)
            list_move(&chunk->list, &pcpu_chunk_lists[slot]);
        else
            list_move_tail(&chunk->list, &pcpu_chunk_lists[slot]);
    }
}

static void pcpu_chunk_move(struct pcpu_chunk *chunk, int slot)
{
    __pcpu_chunk_move(chunk, slot, true);
}

/**
 * pcpu_chunk_relocate - put chunk in the appropriate chunk slot
 * @chunk: chunk of interest
 * @oslot: the previous slot it was on
 *
 * This function is called after an allocation or free changed @chunk.
 * New slot according to the changed state is determined and @chunk is
 * moved to the slot.  Note that the reserved chunk is never put on
 * chunk slots.
 *
 * CONTEXT:
 * pcpu_lock.
 */
static void pcpu_chunk_relocate(struct pcpu_chunk *chunk, int oslot)
{
    int nslot = pcpu_chunk_slot(chunk);

    /* leave isolated chunks in-place */
    if (chunk->isolated)
        return;

    if (oslot != nslot)
        __pcpu_chunk_move(chunk, nslot, oslot < nslot);
}

/**
 * pcpu_setup_first_chunk - initialize the first percpu chunk
 * @ai: pcpu_alloc_info describing how to percpu area is shaped
 * @base_addr: mapped address
 *
 * Initialize the first percpu chunk which contains the kernel static
 * percpu area.  This function is to be called from arch percpu area
 * setup path.
 *
 * @ai contains all information necessary to initialize the first
 * chunk and prime the dynamic percpu allocator.
 *
 * @ai->static_size is the size of static percpu area.
 *
 * @ai->reserved_size, if non-zero, specifies the amount of bytes to
 * reserve after the static area in the first chunk.  This reserves
 * the first chunk such that it's available only through reserved
 * percpu allocation.  This is primarily used to serve module percpu
 * static areas on architectures where the addressing model has
 * limited offset range for symbol relocations to guarantee module
 * percpu symbols fall inside the relocatable range.
 *
 * @ai->dyn_size determines the number of bytes available for dynamic
 * allocation in the first chunk.  The area between @ai->static_size +
 * @ai->reserved_size + @ai->dyn_size and @ai->unit_size is unused.
 *
 * @ai->unit_size specifies unit size and must be aligned to PAGE_SIZE
 * and equal to or larger than @ai->static_size + @ai->reserved_size +
 * @ai->dyn_size.
 *
 * @ai->atom_size is the allocation atom size and used as alignment
 * for vm areas.
 *
 * @ai->alloc_size is the allocation size and always multiple of
 * @ai->atom_size.  This is larger than @ai->atom_size if
 * @ai->unit_size is larger than @ai->atom_size.
 *
 * @ai->nr_groups and @ai->groups describe virtual memory layout of
 * percpu areas.  Units which should be colocated are put into the
 * same group.  Dynamic VM areas will be allocated according to these
 * groupings.  If @ai->nr_groups is zero, a single group containing
 * all units is assumed.
 *
 * The caller should have mapped the first chunk at @base_addr and
 * copied static data to each unit.
 *
 * The first chunk will always contain a static and a dynamic region.
 * However, the static region is not managed by any chunk.  If the first
 * chunk also contains a reserved region, it is served by two chunks -
 * one for the reserved region and one for the dynamic region.  They
 * share the same vm, but use offset regions in the area allocation map.
 * The chunk serving the dynamic region is circulated in the chunk slots
 * and available for dynamic allocation like any other chunk.
 */
void __init
pcpu_setup_first_chunk(const struct pcpu_alloc_info *ai, void *base_addr)
{
    int map_size;
    int *unit_map;
    unsigned long *unit_off;
    unsigned int cpu;
    size_t alloc_size;
    int group, unit, i;
    unsigned long tmp_addr;
    struct pcpu_chunk *chunk;
    size_t *group_sizes;
    unsigned long *group_offsets;
    size_t static_size, dyn_size;
    size_t size_sum = ai->static_size + ai->reserved_size + ai->dyn_size;

#define PCPU_SETUP_BUG_ON(cond) do {                    \
    if (unlikely(cond)) {                               \
        pr_emerg("failed to initialize, %s\n", #cond);  \
        pr_emerg("cpu_possible_mask=%*pb\n",            \
                 cpumask_pr_args(cpu_possible_mask));   \
        pcpu_dump_alloc_info(KERN_EMERG, ai);           \
        BUG();                                          \
    }                                                   \
} while (0)

    /* sanity checks */
    PCPU_SETUP_BUG_ON(ai->nr_groups <= 0);
    PCPU_SETUP_BUG_ON(!ai->static_size);
    PCPU_SETUP_BUG_ON(offset_in_page(__per_cpu_start));

    PCPU_SETUP_BUG_ON(!base_addr);
    PCPU_SETUP_BUG_ON(offset_in_page(base_addr));
    PCPU_SETUP_BUG_ON(ai->unit_size < size_sum);
    PCPU_SETUP_BUG_ON(offset_in_page(ai->unit_size));
    PCPU_SETUP_BUG_ON(ai->unit_size < PCPU_MIN_UNIT_SIZE);
    PCPU_SETUP_BUG_ON(!IS_ALIGNED(ai->unit_size, PCPU_BITMAP_BLOCK_SIZE));
    PCPU_SETUP_BUG_ON(ai->dyn_size < PERCPU_DYNAMIC_EARLY_SIZE);
    PCPU_SETUP_BUG_ON(!ai->dyn_size);
    PCPU_SETUP_BUG_ON(!IS_ALIGNED(ai->reserved_size, PCPU_MIN_ALLOC_SIZE));
    PCPU_SETUP_BUG_ON(!(IS_ALIGNED(PCPU_BITMAP_BLOCK_SIZE, PAGE_SIZE) ||
                        IS_ALIGNED(PAGE_SIZE, PCPU_BITMAP_BLOCK_SIZE)));
    PCPU_SETUP_BUG_ON(pcpu_verify_alloc_info(ai) < 0);

    /* process group information and build config tables accordingly */
    alloc_size = ai->nr_groups * sizeof(group_offsets[0]);
    group_offsets = memblock_alloc(alloc_size, SMP_CACHE_BYTES);
    if (!group_offsets)
        panic("%s: Failed to allocate %zu bytes\n", __func__, alloc_size);

    alloc_size = ai->nr_groups * sizeof(group_sizes[0]);
    group_sizes = memblock_alloc(alloc_size, SMP_CACHE_BYTES);
    if (!group_sizes)
        panic("%s: Failed to allocate %zu bytes\n", __func__, alloc_size);

    alloc_size = nr_cpu_ids * sizeof(unit_map[0]);
    unit_map = memblock_alloc(alloc_size, SMP_CACHE_BYTES);
    if (!unit_map)
        panic("%s: Failed to allocate %zu bytes\n", __func__, alloc_size);

    alloc_size = nr_cpu_ids * sizeof(unit_off[0]);
    unit_off = memblock_alloc(alloc_size, SMP_CACHE_BYTES);
    if (!unit_off)
        panic("%s: Failed to allocate %zu bytes\n", __func__, alloc_size);

    for (cpu = 0; cpu < nr_cpu_ids; cpu++)
        unit_map[cpu] = UINT_MAX;

    pcpu_low_unit_cpu = NR_CPUS;
    pcpu_high_unit_cpu = NR_CPUS;

    for (group = 0, unit = 0; group < ai->nr_groups; group++, unit += i) {
        const struct pcpu_group_info *gi = &ai->groups[group];

        group_offsets[group] = gi->base_offset;
        group_sizes[group] = gi->nr_units * ai->unit_size;

        for (i = 0; i < gi->nr_units; i++) {
            cpu = gi->cpu_map[i];
            if (cpu == NR_CPUS)
                continue;

            PCPU_SETUP_BUG_ON(cpu >= nr_cpu_ids);
            PCPU_SETUP_BUG_ON(!cpu_possible(cpu));
            PCPU_SETUP_BUG_ON(unit_map[cpu] != UINT_MAX);

            unit_map[cpu] = unit + i;
            unit_off[cpu] = gi->base_offset + i * ai->unit_size;

            /* determine low/high unit_cpu */
            if (pcpu_low_unit_cpu == NR_CPUS ||
                unit_off[cpu] < unit_off[pcpu_low_unit_cpu])
                pcpu_low_unit_cpu = cpu;
            if (pcpu_high_unit_cpu == NR_CPUS ||
                unit_off[cpu] > unit_off[pcpu_high_unit_cpu])
                pcpu_high_unit_cpu = cpu;
        }
    }
    pcpu_nr_units = unit;

    for_each_possible_cpu(cpu)
        PCPU_SETUP_BUG_ON(unit_map[cpu] == UINT_MAX);

    /* we're done parsing the input, undefine BUG macro and dump config */
#undef PCPU_SETUP_BUG_ON

    pcpu_dump_alloc_info(KERN_DEBUG, ai);

    pcpu_nr_groups = ai->nr_groups;
    pcpu_group_offsets = group_offsets;
    pcpu_group_sizes = group_sizes;
    pcpu_unit_map = unit_map;
    pcpu_unit_offsets = unit_off;

    /* determine basic parameters */
    pcpu_unit_pages = ai->unit_size >> PAGE_SHIFT;
    pcpu_unit_size = pcpu_unit_pages << PAGE_SHIFT;
    pcpu_atom_size = ai->atom_size;
    pcpu_chunk_struct_size = struct_size(chunk, populated,
                                         BITS_TO_LONGS(pcpu_unit_pages));

    pcpu_stats_save_ai(ai);

    /*
     * Allocate chunk slots.  The slots after the active slots are:
     *   sidelined_slot - isolated, depopulated chunks
     *   free_slot - fully free chunks
     *   to_depopulate_slot - isolated, chunks to depopulate
     */
    pcpu_sidelined_slot = __pcpu_size_to_slot(pcpu_unit_size) + 1;
    pcpu_free_slot = pcpu_sidelined_slot + 1;
    pcpu_to_depopulate_slot = pcpu_free_slot + 1;
    pcpu_nr_slots = pcpu_to_depopulate_slot + 1;
    pcpu_chunk_lists =
        memblock_alloc(pcpu_nr_slots * sizeof(pcpu_chunk_lists[0]),
                       SMP_CACHE_BYTES);
    if (!pcpu_chunk_lists)
        panic("%s: Failed to allocate %zu bytes\n", __func__,
              pcpu_nr_slots * sizeof(pcpu_chunk_lists[0]));

    for (i = 0; i < pcpu_nr_slots; i++)
        INIT_LIST_HEAD(&pcpu_chunk_lists[i]);

    /*
     * The end of the static region needs to be aligned with the
     * minimum allocation size as this offsets the reserved and
     * dynamic region.  The first chunk ends page aligned by
     * expanding the dynamic region, therefore the dynamic region
     * can be shrunk to compensate while still staying above the
     * configured sizes.
     */
    static_size = ALIGN(ai->static_size, PCPU_MIN_ALLOC_SIZE);
    dyn_size = ai->dyn_size - (static_size - ai->static_size);

    /*
     * Initialize first chunk.
     * If the reserved_size is non-zero, this initializes the reserved
     * chunk.  If the reserved_size is zero, the reserved chunk is NULL
     * and the dynamic region is initialized here.  The first chunk,
     * pcpu_first_chunk, will always point to the chunk that serves
     * the dynamic region.
     */
    tmp_addr = (unsigned long)base_addr + static_size;
    map_size = ai->reserved_size ?: dyn_size;
    chunk = pcpu_alloc_first_chunk(tmp_addr, map_size);

    /* init dynamic chunk if necessary */
    if (ai->reserved_size) {
        pcpu_reserved_chunk = chunk;

        tmp_addr = (unsigned long)base_addr + static_size + ai->reserved_size;
        map_size = dyn_size;
        chunk = pcpu_alloc_first_chunk(tmp_addr, map_size);
    }

    /* link the first chunk in */
    pcpu_first_chunk = chunk;
    pcpu_nr_empty_pop_pages = pcpu_first_chunk->nr_empty_pop_pages;
    pcpu_chunk_relocate(pcpu_first_chunk, -1);

    /* include all regions of the first chunk */
    pcpu_nr_populated += PFN_DOWN(size_sum);

    /* we're done */
    pcpu_base_addr = base_addr;
}

static void * __init pcpu_fc_alloc(unsigned int cpu, size_t size, size_t align,
                   pcpu_fc_cpu_to_node_fn_t cpu_to_nd_fn)
{
    const unsigned long goal = __pa(MAX_DMA_ADDRESS);
    return memblock_alloc_from(size, align, goal);
}

static void __init pcpu_fc_free(void *ptr, size_t size)
{
    memblock_free(ptr, size);
}

/**
 * pcpu_embed_first_chunk - embed the first percpu chunk into bootmem
 * @reserved_size: the size of reserved percpu area in bytes
 * @dyn_size: minimum free size for dynamic allocation in bytes
 * @atom_size: allocation atom size
 * @cpu_distance_fn: callback to determine distance between cpus, optional
 * @alloc_fn: function to allocate percpu page
 * @free_fn: function to free percpu page
 *
 * This is a helper to ease setting up embedded first percpu chunk and
 * can be called where pcpu_setup_first_chunk() is expected.
 *
 * If this function is used to setup the first chunk, it is allocated
 * by calling @alloc_fn and used as-is without being mapped into
 * vmalloc area.  Allocations are always whole multiples of @atom_size
 * aligned to @atom_size.
 *
 * This enables the first chunk to piggy back on the linear physical
 * mapping which often uses larger page size.  Please note that this
 * can result in very sparse cpu->unit mapping on NUMA machines thus
 * requiring large vmalloc address space.  Don't use this allocator if
 * vmalloc space is not orders of magnitude larger than distances
 * between node memory addresses (ie. 32bit NUMA machines).
 *
 * @dyn_size specifies the minimum dynamic area size.
 *
 * If the needed size is smaller than the minimum or specified unit
 * size, the leftover is returned using @free_fn.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
int __init pcpu_embed_first_chunk(size_t reserved_size, size_t dyn_size,
                                  size_t atom_size,
                                  pcpu_fc_cpu_distance_fn_t cpu_distance_fn,
                                  pcpu_fc_cpu_to_node_fn_t cpu_to_nd_fn)
{
    struct pcpu_alloc_info *ai;
    size_t size_sum, areas_size;
    unsigned long max_distance;
    void **areas = NULL;
    void *base = (void *)ULONG_MAX;
    int group, i, highest_group, rc = 0;

    ai = pcpu_build_alloc_info(reserved_size, dyn_size, atom_size,
                               cpu_distance_fn);
    if (IS_ERR(ai))
        return PTR_ERR(ai);

    size_sum = ai->static_size + ai->reserved_size + ai->dyn_size;
    areas_size = PFN_ALIGN(ai->nr_groups * sizeof(void *));

    areas = memblock_alloc(areas_size, SMP_CACHE_BYTES);
    if (!areas) {
        rc = -ENOMEM;
        goto out_free;
    }

    /* allocate, copy and determine base address & max_distance */
    highest_group = 0;
    for (group = 0; group < ai->nr_groups; group++) {
        void *ptr;
        unsigned int cpu = NR_CPUS;
        struct pcpu_group_info *gi = &ai->groups[group];

        for (i = 0; i < gi->nr_units && cpu == NR_CPUS; i++)
            cpu = gi->cpu_map[i];
        BUG_ON(cpu == NR_CPUS);

        /* allocate space for the whole group */
        ptr = pcpu_fc_alloc(cpu, gi->nr_units * ai->unit_size, atom_size,
                            cpu_to_nd_fn);
        if (!ptr) {
            rc = -ENOMEM;
            goto out_free_areas;
        }
        areas[group] = ptr;

        base = min(ptr, base);
        if (ptr > areas[highest_group])
            highest_group = group;
    }
    max_distance = areas[highest_group] - base;
    max_distance += ai->unit_size * ai->groups[highest_group].nr_units;

    /* warn if maximum distance is further than 75% of vmalloc space */
    if (max_distance > VMALLOC_TOTAL * 3 / 4) {
        pr_warn("max_distance=0x%lx too large for vmalloc space 0x%lx\n",
                max_distance, VMALLOC_TOTAL);
    }

    /*
     * Copy data and free unused parts.  This should happen after all
     * allocations are complete; otherwise, we may end up with
     * overlapping groups.
     */
    for (group = 0; group < ai->nr_groups; group++) {
        void *ptr = areas[group];
        struct pcpu_group_info *gi = &ai->groups[group];

        for (i = 0; i < gi->nr_units; i++, ptr += ai->unit_size) {
            if (gi->cpu_map[i] == NR_CPUS) {
                /* unused unit, free whole */
                pcpu_fc_free(ptr, ai->unit_size);
                continue;
            }
            /* copy and return the unused part */
            memcpy(ptr, __per_cpu_load, ai->static_size);
            pcpu_fc_free(ptr + size_sum, ai->unit_size - size_sum);
        }
    }

    /* base address is now known, determine group base offsets */
    for (group = 0; group < ai->nr_groups; group++) {
        ai->groups[group].base_offset = areas[group] - base;
    }

    pr_info("Embedded %zu pages/cpu s%zu r%zu d%zu u%zu\n",
            PFN_DOWN(size_sum), ai->static_size, ai->reserved_size,
            ai->dyn_size, ai->unit_size);

    pcpu_setup_first_chunk(ai, base);
    goto out_free;

 out_free_areas:
    for (group = 0; group < ai->nr_groups; group++)
        if (areas[group])
            pcpu_fc_free(areas[group],
                         ai->groups[group].nr_units * ai->unit_size);

 out_free:
    pcpu_free_alloc_info(ai);
    if (areas)
        memblock_free(areas, areas_size);
    return rc;
}

/**
 * setup_per_cpu_areas - setup percpu areas
 *
 * Arch code has already allocated and initialized percpu areas.  All
 * this function has to do is to teach the determined layout to the
 * dynamic percpu allocator, which happens to be more complex than
 * creating whole new ones using helpers.
 */
void __init setup_per_cpu_areas(void)
{
    int rc;
    unsigned int cpu;
    unsigned long delta;

    /*
     * Always reserve area for module percpu variables.  That's
     * what the legacy allocator did.
     */
    rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE, PERCPU_DYNAMIC_RESERVE,
                                PAGE_SIZE, NULL, NULL);
    if (rc < 0)
        panic("Failed to initialize percpu areas.");

    delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
    for_each_possible_cpu(cpu)
        __per_cpu_offset[cpu] = delta + pcpu_unit_offsets[cpu];
}

/**
 * pcpu_check_block_hint - check against the contig hint
 * @block: block of interest
 * @bits: size of allocation
 * @align: alignment of area (max PAGE_SIZE)
 *
 * Check to see if the allocation can fit in the block's contig hint.
 * Note, a chunk uses the same hints as a block so this can also check against
 * the chunk's contig hint.
 */
static bool pcpu_check_block_hint(struct pcpu_block_md *block, int bits,
                  size_t align)
{
    int bit_off = ALIGN(block->contig_hint_start, align) -
        block->contig_hint_start;

    return bit_off + bits <= block->contig_hint;
}


/**
 * pcpu_is_populated - determines if the region is populated
 * @chunk: chunk of interest
 * @bit_off: chunk offset
 * @bits: size of area
 * @next_off: return value for the next offset to start searching
 *
 * For atomic allocations, check if the backing pages are populated.
 *
 * RETURNS:
 * Bool if the backing pages are populated.
 * next_index is to skip over unpopulated blocks in pcpu_find_block_fit.
 */
static bool pcpu_is_populated(struct pcpu_chunk *chunk,
                              int bit_off, int bits, int *next_off)
{
    unsigned int page_start, page_end, rs, re;

    page_start = PFN_DOWN(bit_off * PCPU_MIN_ALLOC_SIZE);
    page_end = PFN_UP((bit_off + bits) * PCPU_MIN_ALLOC_SIZE);

    rs = page_start;
    bitmap_next_clear_region(chunk->populated, &rs, &re, page_end);
    if (rs >= page_end)
        return true;

    *next_off = re * PAGE_SIZE / PCPU_MIN_ALLOC_SIZE;
    return false;
}

/**
 * pcpu_find_block_fit - finds the block index to start searching
 * @chunk: chunk of interest
 * @alloc_bits: size of request in allocation units
 * @align: alignment of area (max PAGE_SIZE bytes)
 * @pop_only: use populated regions only
 *
 * Given a chunk and an allocation spec, find the offset to begin searching
 * for a free region.  This iterates over the bitmap metadata blocks to
 * find an offset that will be guaranteed to fit the requirements.  It is
 * not quite first fit as if the allocation does not fit in the contig hint
 * of a block or chunk, it is skipped.  This errs on the side of caution
 * to prevent excess iteration.  Poor alignment can cause the allocator to
 * skip over blocks and chunks that have valid free areas.
 *
 * RETURNS:
 * The offset in the bitmap to begin searching.
 * -1 if no offset is found.
 */
static int
pcpu_find_block_fit(struct pcpu_chunk *chunk, int alloc_bits, size_t align,
                    bool pop_only)
{
    int bit_off, bits, next_off;
    struct pcpu_block_md *chunk_md = &chunk->chunk_md;

    /*
     * This is an optimization to prevent scanning by assuming if the
     * allocation cannot fit in the global hint, there is memory pressure
     * and creating a new chunk would happen soon.
     */
    if (!pcpu_check_block_hint(chunk_md, alloc_bits, align))
        return -1;

    bit_off = pcpu_next_hint(chunk_md, alloc_bits);
    bits = 0;
    pcpu_for_each_fit_region(chunk, alloc_bits, align, bit_off, bits) {
        if (!pop_only || pcpu_is_populated(chunk, bit_off, bits, &next_off))
            break;

        bit_off = next_off;
        bits = 0;
    }

    if (bit_off == pcpu_chunk_map_bits(chunk))
        return -1;

    return bit_off;
}

/*
 * pcpu_find_zero_area - modified from bitmap_find_next_zero_area_off()
 * @map: the address to base the search on
 * @size: the bitmap size in bits
 * @start: the bitnumber to start searching at
 * @nr: the number of zeroed bits we're looking for
 * @align_mask: alignment mask for zero area
 * @largest_off: offset of the largest area skipped
 * @largest_bits: size of the largest area skipped
 *
 * The @align_mask should be one less than a power of 2.
 *
 * This is a modified version of bitmap_find_next_zero_area_off() to remember
 * the largest area that was skipped.  This is imperfect, but in general is
 * good enough.  The largest remembered region is the largest failed region
 * seen.  This does not include anything we possibly skipped due to alignment.
 * pcpu_block_update_scan() does scan backwards to try and recover what was
 * lost to alignment.  While this can cause scanning to miss earlier possible
 * free areas, smaller allocations will eventually fill those holes.
 */
static unsigned long
pcpu_find_zero_area(unsigned long *map,
                    unsigned long size,
                    unsigned long start,
                    unsigned long nr,
                    unsigned long align_mask,
                    unsigned long *largest_off,
                    unsigned long *largest_bits)
{
    unsigned long index, end, i, area_off, area_bits;
again:
    index = find_next_zero_bit(map, size, start);

    /* Align allocation */
    index = __ALIGN_MASK(index, align_mask);
    area_off = index;

    end = index + nr;
    if (end > size)
        return end;
    i = find_next_bit(map, end, index);
    if (i < end) {
        area_bits = i - area_off;
        /* remember largest unused area with best alignment */
        if (area_bits > *largest_bits ||
            (area_bits == *largest_bits && *largest_off &&
             (!area_off || __ffs(area_off) > __ffs(*largest_off)))) {
            *largest_off = area_off;
            *largest_bits = area_bits;
        }

        start = i + 1;
        goto again;
    }
    return index;
}

/*
 * pcpu_block_update_scan - update a block given a free area from a scan
 * @chunk: chunk of interest
 * @bit_off: chunk offset
 * @bits: size of free area
 *
 * Finding the final allocation spot first goes through pcpu_find_block_fit()
 * to find a block that can hold the allocation and then pcpu_alloc_area()
 * where a scan is used.  When allocations require specific alignments,
 * we can inadvertently create holes which will not be seen in the alloc
 * or free paths.
 *
 * This takes a given free area hole and updates a block as it may change the
 * scan_hint.  We need to scan backwards to ensure we don't miss free bits
 * from alignment.
 */
static void
pcpu_block_update_scan(struct pcpu_chunk *chunk, int bit_off, int bits)
{
    int s_index, l_bit;
    struct pcpu_block_md *block;
    int s_off = pcpu_off_to_block_off(bit_off);
    int e_off = s_off + bits;

    if (e_off > PCPU_BITMAP_BLOCK_BITS)
        return;

    s_index = pcpu_off_to_block_index(bit_off);
    block = chunk->md_blocks + s_index;

    /* scan backwards in case of alignment skipping free bits */
    l_bit = find_last_bit(pcpu_index_alloc_map(chunk, s_index), s_off);
    s_off = (s_off == l_bit) ? 0 : l_bit + 1;

    pcpu_block_update(block, s_off, e_off);
}

/**
 * pcpu_alloc_area - allocates an area from a pcpu_chunk
 * @chunk: chunk of interest
 * @alloc_bits: size of request in allocation units
 * @align: alignment of area (max PAGE_SIZE)
 * @start: bit_off to start searching
 *
 * This function takes in a @start offset to begin searching to fit an
 * allocation of @alloc_bits with alignment @align.  It needs to scan
 * the allocation map because if it fits within the block's contig hint,
 * @start will be block->first_free. This is an attempt to fill the
 * allocation prior to breaking the contig hint.  The allocation and
 * boundary maps are updated accordingly if it confirms a valid
 * free area.
 *
 * RETURNS:
 * Allocated addr offset in @chunk on success.
 * -1 if no matching area is found.
 */
static int
pcpu_alloc_area(struct pcpu_chunk *chunk, int alloc_bits, size_t align,
                int start)
{
    int bit_off, end, oslot;
    unsigned long area_off = 0, area_bits = 0;
    size_t align_mask = (align) ? (align - 1) : 0;
    struct pcpu_block_md *chunk_md = &chunk->chunk_md;

    oslot = pcpu_chunk_slot(chunk);

    /*
     * Search to find a fit.
     */
    end = min_t(int, start + alloc_bits + PCPU_BITMAP_BLOCK_BITS,
                pcpu_chunk_map_bits(chunk));
    bit_off = pcpu_find_zero_area(chunk->alloc_map, end, start, alloc_bits,
                                  align_mask, &area_off, &area_bits);
    if (bit_off >= end)
        return -1;

    if (area_bits)
        pcpu_block_update_scan(chunk, area_off, area_bits);

    /* update alloc map */
    bitmap_set(chunk->alloc_map, bit_off, alloc_bits);

    /* update boundary map */
    set_bit(bit_off, chunk->bound_map);
    bitmap_clear(chunk->bound_map, bit_off + 1, alloc_bits - 1);
    set_bit(bit_off + alloc_bits, chunk->bound_map);

    chunk->free_bytes -= alloc_bits * PCPU_MIN_ALLOC_SIZE;

    /* update first free bit */
    if (bit_off == chunk_md->first_free)
        chunk_md->first_free = find_next_zero_bit(chunk->alloc_map,
                                                  pcpu_chunk_map_bits(chunk),
                                                  bit_off + alloc_bits);

    pcpu_block_update_hint_alloc(chunk, bit_off, alloc_bits);

    pcpu_chunk_relocate(chunk, oslot);

    return bit_off * PCPU_MIN_ALLOC_SIZE;
}

static void pcpu_reintegrate_chunk(struct pcpu_chunk *chunk)
{
    if (chunk->isolated) {
        chunk->isolated = false;
        pcpu_nr_empty_pop_pages += chunk->nr_empty_pop_pages;
        pcpu_chunk_relocate(chunk, -1);
    }
}

/**
 * pcpu_block_update_hint_free - updates the block hints on the free path
 * @chunk: chunk of interest
 * @bit_off: chunk offset
 * @bits: size of request
 *
 * Updates metadata for the allocation path.  This avoids a blind block
 * refresh by making use of the block contig hints.  If this fails, it scans
 * forward and backward to determine the extent of the free area.  This is
 * capped at the boundary of blocks.
 *
 * A chunk update is triggered if a page becomes free, a block becomes free,
 * or the free spans across blocks.  This tradeoff is to minimize iterating
 * over the block metadata to update chunk_md->contig_hint.
 * chunk_md->contig_hint may be off by up to a page, but it will never be more
 * than the available space.  If the contig hint is contained in one block, it
 * will be accurate.
 */
static void
pcpu_block_update_hint_free(struct pcpu_chunk *chunk, int bit_off, int bits)
{
    int nr_empty_pages = 0;
    struct pcpu_block_md *s_block, *e_block, *block;
    int s_index, e_index;   /* block indexes of the freed allocation */
    int s_off, e_off;   /* block offsets of the freed allocation */
    int start, end;     /* start and end of the whole free area */

    /*
     * Calculate per block offsets.
     * The calculation uses an inclusive range, but the resulting offsets
     * are [start, end).  e_index always points to the last block in the
     * range.
     */
    s_index = pcpu_off_to_block_index(bit_off);
    e_index = pcpu_off_to_block_index(bit_off + bits - 1);
    s_off = pcpu_off_to_block_off(bit_off);
    e_off = pcpu_off_to_block_off(bit_off + bits - 1) + 1;

    s_block = chunk->md_blocks + s_index;
    e_block = chunk->md_blocks + e_index;

    /*
     * Check if the freed area aligns with the block->contig_hint.
     * If it does, then the scan to find the beginning/end of the
     * larger free area can be avoided.
     *
     * start and end refer to beginning and end of the free area
     * within each their respective blocks.  This is not necessarily
     * the entire free area as it may span blocks past the beginning
     * or end of the block.
     */
    start = s_off;
    if (s_off == s_block->contig_hint + s_block->contig_hint_start) {
        start = s_block->contig_hint_start;
    } else {
        /*
         * Scan backwards to find the extent of the free area.
         * find_last_bit returns the starting bit, so if the start bit
         * is returned, that means there was no last bit and the
         * remainder of the chunk is free.
         */
        int l_bit = find_last_bit(pcpu_index_alloc_map(chunk, s_index), start);
        start = (start == l_bit) ? 0 : l_bit + 1;
    }

    end = e_off;
    if (e_off == e_block->contig_hint_start)
        end = e_block->contig_hint_start + e_block->contig_hint;
    else
        end = find_next_bit(pcpu_index_alloc_map(chunk, e_index),
                    PCPU_BITMAP_BLOCK_BITS, end);

    /* update s_block */
    e_off = (s_index == e_index) ? end : PCPU_BITMAP_BLOCK_BITS;
    if (!start && e_off == PCPU_BITMAP_BLOCK_BITS)
        nr_empty_pages++;
    pcpu_block_update(s_block, start, e_off);

    /* freeing in the same block */
    if (s_index != e_index) {
        /* update e_block */
        if (end == PCPU_BITMAP_BLOCK_BITS)
            nr_empty_pages++;
        pcpu_block_update(e_block, 0, end);

        /* reset md_blocks in the middle */
        nr_empty_pages += (e_index - s_index - 1);
        for (block = s_block + 1; block < e_block; block++) {
            block->first_free = 0;
            block->scan_hint = 0;
            block->contig_hint_start = 0;
            block->contig_hint = PCPU_BITMAP_BLOCK_BITS;
            block->left_free = PCPU_BITMAP_BLOCK_BITS;
            block->right_free = PCPU_BITMAP_BLOCK_BITS;
        }
    }

    if (nr_empty_pages)
        pcpu_update_empty_pages(chunk, nr_empty_pages);

    /*
     * Refresh chunk metadata when the free makes a block free or spans
     * across blocks.  The contig_hint may be off by up to a page, but if
     * the contig_hint is contained in a block, it will be accurate with
     * the else condition below.
     */
    if (((end - start) >= PCPU_BITMAP_BLOCK_BITS) || s_index != e_index)
        pcpu_chunk_refresh_hint(chunk, true);
    else
        pcpu_block_update(&chunk->chunk_md,
                          pcpu_block_off_to_off(s_index, start), end);
}

/**
 * pcpu_free_area - frees the corresponding offset
 * @chunk: chunk of interest
 * @off: addr offset into chunk
 *
 * This function determines the size of an allocation to free using
 * the boundary bitmap and clears the allocation map.
 *
 * RETURNS:
 * Number of freed bytes.
 */
static int pcpu_free_area(struct pcpu_chunk *chunk, int off)
{
    int bit_off, bits, end, oslot, freed;
    struct pcpu_block_md *chunk_md = &chunk->chunk_md;

    oslot = pcpu_chunk_slot(chunk);

    bit_off = off / PCPU_MIN_ALLOC_SIZE;

    /* find end index */
    end = find_next_bit(chunk->bound_map, pcpu_chunk_map_bits(chunk),
                        bit_off + 1);
    bits = end - bit_off;
    bitmap_clear(chunk->alloc_map, bit_off, bits);

    freed = bits * PCPU_MIN_ALLOC_SIZE;

    /* update metadata */
    chunk->free_bytes += freed;

    /* update first free bit */
    chunk_md->first_free = min(chunk_md->first_free, bit_off);

    pcpu_block_update_hint_free(chunk, bit_off, bits);

    pcpu_chunk_relocate(chunk, oslot);

    return freed;
}

/**
 * pcpu_chunk_populated - post-population bookkeeping
 * @chunk: pcpu_chunk which got populated
 * @page_start: the start page
 * @page_end: the end page
 *
 * Pages in [@page_start,@page_end) have been populated to @chunk.  Update
 * the bookkeeping information accordingly.  Must be called after each
 * successful population.
 */
static void
pcpu_chunk_populated(struct pcpu_chunk *chunk, int page_start, int page_end)
{
    int nr = page_end - page_start;

    bitmap_set(chunk->populated, page_start, nr);
    chunk->nr_populated += nr;
    pcpu_nr_populated += nr;

    pcpu_update_empty_pages(chunk, nr);
}

/**
 * pcpu_alloc - the percpu allocator
 * @size: size of area to allocate in bytes
 * @align: alignment of area (max PAGE_SIZE)
 * @reserved: allocate from the reserved chunk if available
 * @gfp: allocation flags
 *
 * Allocate percpu area of @size bytes aligned at @align.  If @gfp doesn't
 * contain %GFP_KERNEL, the allocation is atomic. If @gfp has __GFP_NOWARN
 * then no warning will be triggered on invalid or failed allocation
 * requests.
 *
 * RETURNS:
 * Percpu pointer to the allocated area on success, NULL on failure.
 */
static void __percpu *
pcpu_alloc(size_t size, size_t align, bool reserved, gfp_t gfp)
{
    bool do_warn;
    bool is_atomic;
    gfp_t pcpu_gfp;
    const char *err;
    void __percpu *ptr;
    unsigned long flags;
    size_t bits, bit_align;
    int slot, off, cpu, ret;
    struct pcpu_chunk *chunk, *next;
    static int warn_limit = 10;

    gfp = current_gfp_context(gfp);
    /* whitelisted flags that can be passed to the backing allocators */
    pcpu_gfp = gfp & (GFP_KERNEL | __GFP_NORETRY | __GFP_NOWARN);
    is_atomic = (gfp & GFP_KERNEL) != GFP_KERNEL;
    do_warn = !(gfp & __GFP_NOWARN);

    /*
     * There is now a minimum allocation size of PCPU_MIN_ALLOC_SIZE,
     * therefore alignment must be a minimum of that many bytes.
     * An allocation may have internal fragmentation from rounding up
     * of up to PCPU_MIN_ALLOC_SIZE - 1 bytes.
     */
    if (unlikely(align < PCPU_MIN_ALLOC_SIZE))
        align = PCPU_MIN_ALLOC_SIZE;

    size = ALIGN(size, PCPU_MIN_ALLOC_SIZE);
    bits = size >> PCPU_MIN_ALLOC_SHIFT;
    bit_align = align >> PCPU_MIN_ALLOC_SHIFT;

    if (unlikely(!size || size > PCPU_MIN_UNIT_SIZE ||
                 align > PAGE_SIZE || !is_power_of_2(align))) {
        WARN(do_warn,
             "illegal size (%zu) or align (%zu) for percpu allocation\n",
             size, align);
        return NULL;
    }

    if (!is_atomic) {
        /*
         * pcpu_balance_workfn() allocates memory under this mutex,
         * and it may wait for memory reclaim. Allow current task
         * to become OOM victim, in case of memory pressure.
         */
        if (gfp & __GFP_NOFAIL) {
            mutex_lock(&pcpu_alloc_mutex);
        } else if (mutex_lock_killable(&pcpu_alloc_mutex)) {
            return NULL;
        }
    }

    spin_lock_irqsave(&pcpu_lock, flags);

    /* serve reserved allocations from the reserved chunk if available */
    if (reserved && pcpu_reserved_chunk) {
        panic("%s: NO reserved!\n", __func__);
#if 0
        chunk = pcpu_reserved_chunk;

        off = pcpu_find_block_fit(chunk, bits, bit_align, is_atomic);
        if (off < 0) {
            err = "alloc from reserved chunk failed";
            goto fail_unlock;
        }

        off = pcpu_alloc_area(chunk, bits, bit_align, off);
        if (off >= 0)
            goto area_found;

        err = "alloc from reserved chunk failed";
        goto fail_unlock;
#endif
    }

restart:
    /* search through normal chunks */
    for (slot = pcpu_size_to_slot(size); slot <= pcpu_free_slot; slot++) {
        list_for_each_entry_safe(chunk, next, &pcpu_chunk_lists[slot], list) {
            off = pcpu_find_block_fit(chunk, bits, bit_align, is_atomic);
            if (off < 0) {
                if (slot < PCPU_SLOT_FAIL_THRESHOLD)
                    pcpu_chunk_move(chunk, 0);
                continue;
            }

            off = pcpu_alloc_area(chunk, bits, bit_align, off);
            if (off >= 0) {
                pcpu_reintegrate_chunk(chunk);
                goto area_found;
            }
        }
    }

    spin_unlock_irqrestore(&pcpu_lock, flags);

    /*
     * No space left.  Create a new chunk.  We don't want multiple
     * tasks to create chunks simultaneously.  Serialize and create iff
     * there's still no empty chunk after grabbing the mutex.
     */
    if (is_atomic) {
        err = "atomic alloc failed, no space left";
        goto fail;
    }

    if (list_empty(&pcpu_chunk_lists[pcpu_free_slot])) {
        chunk = pcpu_create_chunk(pcpu_gfp);
        if (!chunk) {
            err = "failed to allocate new chunk";
            goto fail;
        }

        spin_lock_irqsave(&pcpu_lock, flags);
        pcpu_chunk_relocate(chunk, -1);
    } else {
        spin_lock_irqsave(&pcpu_lock, flags);
    }

    goto restart;

 area_found:
    spin_unlock_irqrestore(&pcpu_lock, flags);

    /* populate if not all pages are already there */
    if (!is_atomic) {
        unsigned int page_start, page_end, rs, re;

        page_start = PFN_DOWN(off);
        page_end = PFN_UP(off + size);

        bitmap_for_each_clear_region(chunk->populated, rs, re,
                                     page_start, page_end) {
            WARN_ON(chunk->immutable);

            ret = pcpu_populate_chunk(chunk, rs, re, pcpu_gfp);

            spin_lock_irqsave(&pcpu_lock, flags);
            if (ret) {
                pcpu_free_area(chunk, off);
                err = "failed to populate";
                goto fail_unlock;
            }
            pcpu_chunk_populated(chunk, rs, re);
            spin_unlock_irqrestore(&pcpu_lock, flags);
        }

        mutex_unlock(&pcpu_alloc_mutex);
    }

#if 0
    if (pcpu_nr_empty_pop_pages < PCPU_EMPTY_POP_PAGES_LOW)
        pcpu_schedule_balance_work();
#endif

    /* clear the areas and return address relative to base address */
    for_each_possible_cpu(cpu)
        memset((void *)pcpu_chunk_addr(chunk, cpu, 0) + off, 0, size);

    ptr = __addr_to_pcpu_ptr(chunk->base_addr + off);
    return ptr;

 fail_unlock:
    spin_unlock_irqrestore(&pcpu_lock, flags);
 fail:
    if (!is_atomic && do_warn && warn_limit) {
        pr_warn("allocation failed, size=%zu align=%zu atomic=%d, %s\n",
                size, align, is_atomic, err);
        //dump_stack();
        if (!--warn_limit)
            pr_info("limit reached, disable warning\n");
    }
    if (is_atomic) {
#if 0
        /* see the flag handling in pcpu_balance_workfn() */
        pcpu_atomic_alloc_failed = true;
        pcpu_schedule_balance_work();
#endif
    } else {
        mutex_unlock(&pcpu_alloc_mutex);
    }

    return NULL;
}

/**
 * __alloc_percpu - allocate dynamic percpu area
 * @size: size of area to allocate in bytes
 * @align: alignment of area (max PAGE_SIZE)
 *
 * Equivalent to __alloc_percpu_gfp(size, align, %GFP_KERNEL).
 */
void __percpu *__alloc_percpu(size_t size, size_t align)
{
    return pcpu_alloc(size, align, false, GFP_KERNEL);
}
EXPORT_SYMBOL_GPL(__alloc_percpu);

/**
 * pcpu_addr_in_chunk - check if the address is served from this chunk
 * @chunk: chunk of interest
 * @addr: percpu address
 *
 * RETURNS:
 * True if the address is served from this chunk.
 */
static bool pcpu_addr_in_chunk(struct pcpu_chunk *chunk, void *addr)
{
    void *start_addr, *end_addr;

    if (!chunk)
        return false;

    start_addr = chunk->base_addr + chunk->start_offset;
    end_addr = chunk->base_addr + chunk->nr_pages * PAGE_SIZE - chunk->end_offset;

    return addr >= start_addr && addr < end_addr;
}

/* obtain pointer to a chunk from a page struct */
static struct pcpu_chunk *pcpu_get_page_chunk(struct page *page)
{
    return (struct pcpu_chunk *)page->index;
}

/**
 * pcpu_chunk_addr_search - determine chunk containing specified address
 * @addr: address for which the chunk needs to be determined.
 *
 * This is an internal function that handles all but static allocations.
 * Static percpu address values should never be passed into the allocator.
 *
 * RETURNS:
 * The address of the found chunk.
 */
static struct pcpu_chunk *pcpu_chunk_addr_search(void *addr)
{
    /* is it in the dynamic region (first chunk)? */
    if (pcpu_addr_in_chunk(pcpu_first_chunk, addr))
        return pcpu_first_chunk;

    /* is it in the reserved region? */
    if (pcpu_addr_in_chunk(pcpu_reserved_chunk, addr))
        return pcpu_reserved_chunk;

    /*
     * The address is relative to unit0 which might be unused and
     * thus unmapped.  Offset the address to the unit space of the
     * current processor before looking it up in the vmalloc
     * space.  Note that any possible cpu id can be used here, so
     * there's no need to worry about preemption or cpu hotplug.
     */
    addr += pcpu_unit_offsets[raw_smp_processor_id()];
    return pcpu_get_page_chunk(pcpu_addr_to_page(addr));
}

static void pcpu_isolate_chunk(struct pcpu_chunk *chunk)
{
    if (!chunk->isolated) {
        chunk->isolated = true;
        pcpu_nr_empty_pop_pages -= chunk->nr_empty_pop_pages;
    }
    list_move(&chunk->list, &pcpu_chunk_lists[pcpu_to_depopulate_slot]);
}

/**
 * free_percpu - free percpu area
 * @ptr: pointer to area to free
 *
 * Free percpu area @ptr.
 *
 * CONTEXT:
 * Can be called from atomic context.
 */
void free_percpu(void __percpu *ptr)
{
    void *addr;
    struct pcpu_chunk *chunk;
    unsigned long flags;
    int size, off;
    bool need_balance = false;

    if (!ptr)
        return;

    addr = __pcpu_ptr_to_addr(ptr);

    spin_lock_irqsave(&pcpu_lock, flags);

    chunk = pcpu_chunk_addr_search(addr);
    off = addr - chunk->base_addr;

    size = pcpu_free_area(chunk, off);

    /*
     * If there are more than one fully free chunks, wake up grim reaper.
     * If the chunk is isolated, it may be in the process of being
     * reclaimed.  Let reclaim manage cleaning up of that chunk.
     */
    if (!chunk->isolated && chunk->free_bytes == pcpu_unit_size) {
        struct pcpu_chunk *pos;

        list_for_each_entry(pos, &pcpu_chunk_lists[pcpu_free_slot], list)
            if (pos != chunk) {
                need_balance = true;
                break;
            }
    } else if (pcpu_should_reclaim_chunk(chunk)) {
        pcpu_isolate_chunk(chunk);
        need_balance = true;
    }

    spin_unlock_irqrestore(&pcpu_lock, flags);

#if 0
    if (need_balance)
        pcpu_schedule_balance_work();
#endif
}
EXPORT_SYMBOL_GPL(free_percpu);

/**
 * __alloc_percpu_gfp - allocate dynamic percpu area
 * @size: size of area to allocate in bytes
 * @align: alignment of area (max PAGE_SIZE)
 * @gfp: allocation flags
 *
 * Allocate zero-filled percpu area of @size bytes aligned at @align.  If
 * @gfp doesn't contain %GFP_KERNEL, the allocation doesn't block and can
 * be called from any context but is a lot more likely to fail. If @gfp
 * has __GFP_NOWARN then no warning will be triggered on invalid or failed
 * allocation requests.
 *
 * RETURNS:
 * Percpu pointer to the allocated area on success, NULL on failure.
 */
void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp)
{
    return pcpu_alloc(size, align, false, gfp);
}
EXPORT_SYMBOL_GPL(__alloc_percpu_gfp);

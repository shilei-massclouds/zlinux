/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_PERCPU_H
#define __LINUX_PERCPU_H

//#include <linux/mmdebug.h>
#include <linux/preempt.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/printk.h>
#include <linux/pfn.h>
#include <linux/init.h>

#include <asm/percpu.h>

/* minimum unit size, also is the maximum supported allocation size */
#define PCPU_MIN_UNIT_SIZE      PFN_ALIGN(32 << 10)

/* minimum allocation size and shift in bytes */
#define PCPU_MIN_ALLOC_SHIFT    2
#define PCPU_MIN_ALLOC_SIZE     (1 << PCPU_MIN_ALLOC_SHIFT)

#define PERCPU_MODULE_RESERVE   (8 << 10)
#define PERCPU_DYNAMIC_RESERVE  (28 << 10)

/*
 * Percpu allocator can serve percpu allocations before slab is
 * initialized which allows slab to depend on the percpu allocator.
 * The following two parameters decide how much resource to
 * preallocate for this.  Keep PERCPU_DYNAMIC_RESERVE equal to or
 * larger than PERCPU_DYNAMIC_EARLY_SIZE.
 */
#define PERCPU_DYNAMIC_EARLY_SLOTS  128
#define PERCPU_DYNAMIC_EARLY_SIZE   (12 << 10)

/*
 * The PCPU_BITMAP_BLOCK_SIZE must be the same size as PAGE_SIZE as the
 * updating of hints is used to manage the nr_empty_pop_pages in both
 * the chunk and globally.
 */
#define PCPU_BITMAP_BLOCK_SIZE PAGE_SIZE
#define PCPU_BITMAP_BLOCK_BITS (PCPU_BITMAP_BLOCK_SIZE >> PCPU_MIN_ALLOC_SHIFT)

extern void *pcpu_base_addr;
extern const unsigned long *pcpu_unit_offsets;

struct pcpu_group_info {
    int             nr_units;       /* aligned # of units */
    unsigned long   base_offset;    /* base address offset */
    unsigned int    *cpu_map; /* unit->cpu map, empty entries contain NR_CPUS */
};

struct pcpu_alloc_info {
    size_t  static_size;
    size_t  reserved_size;
    size_t  dyn_size;
    size_t  unit_size;
    size_t  atom_size;
    size_t  alloc_size;
    size_t  __ai_size;  /* internal, don't use */
    int     nr_groups;  /* 0 if grouping unnecessary */
    struct pcpu_group_info  groups[];
};

extern void __init setup_per_cpu_areas(void);

extern void __percpu *__alloc_percpu(size_t size, size_t align) __alloc_size(1);

extern void free_percpu(void __percpu *__pdata);

typedef int (pcpu_fc_cpu_to_node_fn_t)(int cpu);
typedef int (pcpu_fc_cpu_distance_fn_t)(unsigned int from, unsigned int to);

#define alloc_percpu(type) \
    (typeof(type) __percpu *)__alloc_percpu(sizeof(type), __alignof__(type))


extern void __percpu *__alloc_percpu_gfp(size_t size, size_t align, gfp_t gfp)
    __alloc_size(1);

#define alloc_percpu_gfp(type, gfp) \
    (typeof(type) __percpu *)__alloc_percpu_gfp(sizeof(type), \
                                                __alignof__(type), gfp)

#endif /* __LINUX_PERCPU_H */

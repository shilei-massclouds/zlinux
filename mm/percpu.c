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

#if 0
#include <linux/bitmap.h>
#endif
#include <linux/memblock.h>
#include <linux/err.h>
//#include <linux/lcm.h>
#include <linux/list.h>
#include <linux/log2.h>
#include <linux/mm.h>
#include <linux/module.h>
//#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/pfn.h>
//#include <linux/slab.h>
#include <linux/spinlock.h>
#if 0
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/kmemleak.h>
#endif
#include <linux/sched.h>
#if 0
#include <linux/sched/mm.h>
#include <linux/memcontrol.h>

#include <asm/cacheflush.h>
#endif
#include <asm/sections.h>
#include <asm/tlbflush.h>
#include <asm/io.h>

#if 0
#include "percpu-internal.h"
#endif

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

void __init setup_per_cpu_areas(void)
{
#if 0
    unsigned long delta;
    unsigned int cpu;
    int rc;

    /*
     * Always reserve area for module percpu variables.  That's
     * what the legacy allocator did.
     */
    rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
                    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE, NULL,
                    pcpu_dfl_fc_alloc, pcpu_dfl_fc_free);
    if (rc < 0)
        panic("Failed to initialize percpu areas.");

    delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
    for_each_possible_cpu(cpu)
        __per_cpu_offset[cpu] = delta + pcpu_unit_offsets[cpu];
#endif
}

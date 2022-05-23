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

#ifndef __pcpu_ptr_to_addr
#define __pcpu_ptr_to_addr(ptr) \
    (void __force *)((unsigned long)(ptr) + \
                     (unsigned long)pcpu_base_addr - \
                     (unsigned long)__per_cpu_start)
#endif

/* the address of the first chunk which starts with the kernel static area */
void *pcpu_base_addr __ro_after_init;

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
    panic("%s: NO implementation!\n", __func__);
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

    panic("%s: END\n", __func__);
#if 0
    addr = __pcpu_ptr_to_addr(ptr);

    spin_lock_irqsave(&pcpu_lock, flags);

    chunk = pcpu_chunk_addr_search(addr);
    off = addr - chunk->base_addr;

    size = pcpu_free_area(chunk, off);

    pcpu_memcg_free_hook(chunk, off, size);

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

    trace_percpu_free_percpu(chunk->base_addr, off, ptr);

    spin_unlock_irqrestore(&pcpu_lock, flags);

    if (need_balance)
        pcpu_schedule_balance_work();
#endif
}
EXPORT_SYMBOL_GPL(free_percpu);

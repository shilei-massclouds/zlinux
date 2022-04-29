/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Written by Mark Hemment, 1996 (markhe@nextd.demon.co.uk).
 *
 * (C) SGI 2006, Christoph Lameter
 *  Cleaned up and restructured to ease the addition of alternative
 *  implementations of SLAB allocators.
 * (C) Linux Foundation 2008-2013
 *      Unified interface for all slab allocators
 */

#ifndef _LINUX_SLAB_H
#define _LINUX_SLAB_H

#include <linux/gfp.h>
/*
#include <linux/overflow.h>
*/
#include <linux/types.h>
/*
#include <linux/workqueue.h>
#include <linux/percpu-refcount.h>
*/

struct kmem_cache;

/*
 * Setting ARCH_SLAB_MINALIGN in arch headers allows a different alignment.
 * Intended for arches that get misalignment faults even for 64 bit integer
 * aligned buffers.
 */
#ifndef ARCH_SLAB_MINALIGN
#define ARCH_SLAB_MINALIGN __alignof__(unsigned long long)
#endif

#define __assume_slab_alignment __assume_aligned(ARCH_SLAB_MINALIGN)

void *kmem_cache_alloc(struct kmem_cache *, gfp_t flags)
    __assume_slab_alignment __malloc;

static __always_inline void *
kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node)
{
    return kmem_cache_alloc(s, flags);
}

void kmem_cache_free(struct kmem_cache *, void *);

#endif  /* _LINUX_SLAB_H */

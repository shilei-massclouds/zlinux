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
#include <linux/overflow.h>
#include <linux/types.h>
/*
#include <linux/workqueue.h>
#include <linux/percpu-refcount.h>
*/

/* DEBUG: Red zone objs in a cache */
#define SLAB_RED_ZONE           ((slab_flags_t __force)0x00000400U)

/* DEBUG: Poison objects */
#define SLAB_POISON             ((slab_flags_t __force)0x00000800U)

/* Align objs on cache lines */
#define SLAB_HWCACHE_ALIGN      ((slab_flags_t __force)0x00002000U)

/* Use GFP_DMA memory */
#define SLAB_CACHE_DMA          ((slab_flags_t __force)0x00004000U)
/* Use GFP_DMA32 memory */
#define SLAB_CACHE_DMA32        ((slab_flags_t __force)0x00008000U)

/* DEBUG: Store the last owner for bug hunting */
#define SLAB_STORE_USER         ((slab_flags_t __force)0x00010000U)

/* The following flags affect the page allocator grouping pages by mobility */
/* Objects are reclaimable */
#define SLAB_RECLAIM_ACCOUNT    ((slab_flags_t __force)0x00020000U)

/* Defer freeing slabs to RCU */
#define SLAB_TYPESAFE_BY_RCU    ((slab_flags_t __force)0x00080000U)

/* Avoid kmemleak tracing */
#define SLAB_NOLEAKTRACE        ((slab_flags_t __force)0x00800000U)

#define ARCH_KMALLOC_MINALIGN __alignof__(unsigned long long)

/*
 * kmalloc and friends return ARCH_KMALLOC_MINALIGN aligned
 * pointers. kmem_cache_alloc and friends return ARCH_SLAB_MINALIGN
 * aligned pointers.
 */
#define __assume_kmalloc_alignment  __assume_aligned(ARCH_KMALLOC_MINALIGN)
#define __assume_slab_alignment     __assume_aligned(ARCH_SLAB_MINALIGN)
#define __assume_page_alignment     __assume_aligned(PAGE_SIZE)

/*
 * Kmalloc array related definitions
 */

/*
 * The largest kmalloc size supported by the SLAB allocators is
 * 32 megabyte (2^25) or the maximum allocatable page order if that is
 * less than 32 MB.
 *
 * WARNING: Its not easy to increase this value since the allocators have
 * to do various tricks to work around compiler limitations in order to
 * ensure proper constant folding.
 */
#define KMALLOC_SHIFT_HIGH \
    ((MAX_ORDER + PAGE_SHIFT - 1) <= 25 ? (MAX_ORDER + PAGE_SHIFT - 1) : 25)

#define KMALLOC_SHIFT_MAX   KMALLOC_SHIFT_HIGH

#ifndef KMALLOC_SHIFT_LOW
#define KMALLOC_SHIFT_LOW   5
#endif

/*
 * Kmalloc subsystem.
 */
#ifndef KMALLOC_MIN_SIZE
#define KMALLOC_MIN_SIZE (1 << KMALLOC_SHIFT_LOW)
#endif

/*
 * This restriction comes from byte sized index implementation.
 * Page size is normally 2^12 bytes and, in this case, if we want to use
 * byte sized index which can represent 2^8 entries, the size of the object
 * should be equal or greater to 2^12 / 2^8 = 2^4 = 16.
 * If minimum size of kmalloc is less than 16, we use it as minimum object
 * size and give up to use byte sized index.
 */
#define SLAB_OBJ_MIN_SIZE (KMALLOC_MIN_SIZE < 16 ? (KMALLOC_MIN_SIZE) : 16)

/* Maximum allocatable size */
#define KMALLOC_MAX_SIZE        (1UL << KMALLOC_SHIFT_MAX)
/* Maximum size for which we actually use a slab cache */
#define KMALLOC_MAX_CACHE_SIZE  (1UL << KMALLOC_SHIFT_HIGH)
/* Maximum order allocatable via the slab allocator */
#define KMALLOC_MAX_ORDER       (KMALLOC_SHIFT_MAX - PAGE_SHIFT)

/*
 * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
 *
 * Dereferencing ZERO_SIZE_PTR will lead to a distinct access fault.
 *
 * ZERO_SIZE_PTR can be passed to kfree though in the same way that NULL can.
 * Both make kfree a no-op.
 */
#define ZERO_SIZE_PTR ((void *)16)

#define ZERO_OR_NULL_PTR(x) ((unsigned long)(x) <= (unsigned long)ZERO_SIZE_PTR)

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

/*
 * Whenever changing this, take care of that kmalloc_type() and
 * create_kmalloc_caches() still work as intended.
 *
 * KMALLOC_NORMAL can contain only unaccounted objects whereas KMALLOC_CGROUP
 * is for accounted but unreclaimable and non-dma objects. All the other
 * kmem caches can have both accounted and unaccounted objects.
 */
enum kmalloc_cache_type {
    KMALLOC_NORMAL = 0,
    KMALLOC_DMA = KMALLOC_NORMAL,
    KMALLOC_CGROUP = KMALLOC_NORMAL,
    KMALLOC_RECLAIM,
    NR_KMALLOC_TYPES
};

extern struct kmem_cache *
kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1];

/*
 * struct kmem_cache related prototypes
 */
void __init kmem_cache_init(void);
bool slab_is_available(void);

void *kmem_cache_alloc(struct kmem_cache *, gfp_t flags)
    __assume_slab_alignment __malloc;

static __always_inline void *
kmem_cache_alloc_node(struct kmem_cache *s, gfp_t flags, int node)
{
    return kmem_cache_alloc(s, flags);
}

void kmem_cache_free(struct kmem_cache *, void *);

extern void *
kmalloc_order(size_t size, gfp_t flags, unsigned int order)
    __assume_page_alignment __alloc_size(1);

static __always_inline __alloc_size(1)
void *kmalloc_order_trace(size_t size, gfp_t flags, unsigned int order)
{
    return kmalloc_order(size, flags, order);
}

static __always_inline __alloc_size(1)
void *kmalloc_large(size_t size, gfp_t flags)
{
    unsigned int order = get_order(size);
    return kmalloc_order_trace(size, flags, order);
}

/*
 * Figure out which kmalloc slab an allocation of a certain size
 * belongs to.
 * 0 = zero alloc
 * 1 =  65 .. 96 bytes
 * 2 = 129 .. 192 bytes
 * n = 2^(n-1)+1 .. 2^n
 *
 * Note: __kmalloc_index() is compile-time optimized, and not runtime optimized;
 * typical usage is via kmalloc_index() and therefore evaluated at compile-time.
 * Callers where !size_is_constant should only be test modules, where runtime
 * overheads of __kmalloc_index() can be tolerated.  Also see kmalloc_slab().
 */
static __always_inline unsigned int
__kmalloc_index(size_t size, bool size_is_constant)
{
    if (!size)
        return 0;

    if (size <= KMALLOC_MIN_SIZE)
        return KMALLOC_SHIFT_LOW;

    if (KMALLOC_MIN_SIZE <= 32 && size > 64 && size <= 96)
        return 1;
    if (KMALLOC_MIN_SIZE <= 64 && size > 128 && size <= 192)
        return 2;
    if (size <=          8) return 3;
    if (size <=         16) return 4;
    if (size <=         32) return 5;
    if (size <=         64) return 6;
    if (size <=        128) return 7;
    if (size <=        256) return 8;
    if (size <=        512) return 9;
    if (size <=       1024) return 10;
    if (size <=   2 * 1024) return 11;
    if (size <=   4 * 1024) return 12;
    if (size <=   8 * 1024) return 13;
    if (size <=  16 * 1024) return 14;
    if (size <=  32 * 1024) return 15;
    if (size <=  64 * 1024) return 16;
    if (size <= 128 * 1024) return 17;
    if (size <= 256 * 1024) return 18;
    if (size <= 512 * 1024) return 19;
    if (size <= 1024 * 1024) return 20;
    if (size <=  2 * 1024 * 1024) return 21;
    if (size <=  4 * 1024 * 1024) return 22;
    if (size <=  8 * 1024 * 1024) return 23;
    if (size <=  16 * 1024 * 1024) return 24;
    if (size <=  32 * 1024 * 1024) return 25;

    if ((IS_ENABLED(CONFIG_CC_IS_GCC) || CONFIG_CLANG_VERSION >= 110000)
        && !IS_ENABLED(CONFIG_PROFILE_ALL_BRANCHES) && size_is_constant)
        BUILD_BUG_ON_MSG(1, "unexpected size in kmalloc_index()");
    else
        BUG();

    /* Will never be reached. Needed because the compiler may complain */
    return -1;
}
#define kmalloc_index(s) __kmalloc_index(s, true)

/*
 * Define gfp bits that should not be set for KMALLOC_NORMAL.
 */
#define KMALLOC_NOT_NORMAL_BITS __GFP_RECLAIMABLE

static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags)
{
    /*
     * The most common case is KMALLOC_NORMAL, so test for it
     * with a single branch for all the relevant flags.
     */
    if (likely((flags & KMALLOC_NOT_NORMAL_BITS) == 0))
        return KMALLOC_NORMAL;

    /*
     * At least one of the flags has to be set. Their priorities in
     * decreasing order are:
     *  1) __GFP_DMA
     *  2) __GFP_RECLAIMABLE
     *  3) __GFP_ACCOUNT
     */
    return KMALLOC_RECLAIM;
}

void *__kmalloc(size_t size, gfp_t flags)
    __assume_kmalloc_alignment __alloc_size(1);

static __always_inline __alloc_size(3)
void *kmem_cache_alloc_trace(struct kmem_cache *s, gfp_t flags, size_t size)
{
    return kmem_cache_alloc(s, flags);
}

static __always_inline __alloc_size(4) void *
kmem_cache_alloc_node_trace(struct kmem_cache *s, gfp_t gfpflags,
                            int node, size_t size)
{
    return kmem_cache_alloc_trace(s, gfpflags, size);
}

static __always_inline __alloc_size(1) void *
__kmalloc_node(size_t size, gfp_t flags, int node)
{
    return __kmalloc(size, flags);
}

/**
 * kmalloc - allocate memory
 * @size: how many bytes of memory are required.
 * @flags: the type of memory to allocate.
 *
 * kmalloc is the normal method of allocating memory
 * for objects smaller than page size in the kernel.
 *
 * The allocated object address is aligned to at least ARCH_KMALLOC_MINALIGN
 * bytes. For @size of power of two bytes, the alignment is also guaranteed
 * to be at least to the size.
 *
 * The @flags argument may be one of the GFP flags defined at
 * include/linux/gfp.h and described at
 * :ref:`Documentation/core-api/mm-api.rst <mm-api-gfp-flags>`
 *
 * The recommended usage of the @flags is described at
 * :ref:`Documentation/core-api/memory-allocation.rst <memory_allocation>`
 *
 * Below is a brief outline of the most useful GFP flags
 *
 * %GFP_KERNEL
 *  Allocate normal kernel ram. May sleep.
 *
 * %GFP_NOWAIT
 *  Allocation will not sleep.
 *
 * %GFP_ATOMIC
 *  Allocation will not sleep.  May use emergency pools.
 *
 * %GFP_HIGHUSER
 *  Allocate memory from high memory on behalf of user.
 *
 * Also it is possible to set different flags by OR'ing
 * in one or more of the following additional @flags:
 *
 * %__GFP_HIGH
 *  This allocation has high priority and may use emergency pools.
 *
 * %__GFP_NOFAIL
 *  Indicate that this allocation is in no way allowed to fail
 *  (think twice before using).
 *
 * %__GFP_NORETRY
 *  If memory is not immediately available,
 *  then give up at once.
 *
 * %__GFP_NOWARN
 *  If allocation fails, don't issue any warnings.
 *
 * %__GFP_RETRY_MAYFAIL
 *  Try really hard to succeed the allocation but fail
 *  eventually.
 */
static __always_inline __alloc_size(1)
void *kmalloc(size_t size, gfp_t flags)
{
    if (__builtin_constant_p(size)) {
        unsigned int index;

        if (size > KMALLOC_MAX_CACHE_SIZE)
            return kmalloc_large(size, flags);

        index = kmalloc_index(size);
        if (!index)
            return ZERO_SIZE_PTR;

        return kmem_cache_alloc_trace(
            kmalloc_caches[kmalloc_type(flags)][index], flags, size);
    }

    return __kmalloc(size, flags);
}

void kfree(const void *objp);

static __always_inline __alloc_size(1) void *
kmalloc_node(size_t size, gfp_t flags, int node)
{
    if (__builtin_constant_p(size) &&
        size <= KMALLOC_MAX_CACHE_SIZE) {
        unsigned int i = kmalloc_index(size);

        if (!i)
            return ZERO_SIZE_PTR;

        return kmem_cache_alloc_node_trace(
                    kmalloc_caches[kmalloc_type(flags)][i], flags, node, size);
    }

    return __kmalloc_node(size, flags, node);
}

/*
 * Shortcuts
 */
static inline void *kmem_cache_zalloc(struct kmem_cache *k, gfp_t flags)
{
    return kmem_cache_alloc(k, flags | __GFP_ZERO);
}

#endif  /* _LINUX_SLAB_H */

// SPDX-License-Identifier: GPL-2.0
/*
 * Slab allocator functions that are independent of the allocator strategy
 *
 * (C) 2012 Christoph Lameter <cl@linux.com>
 */
#include <linux/slab.h>

#include <linux/mm.h>
#include <linux/poison.h>
/*
#include <linux/interrupt.h>
#include <linux/memory.h>
*/
#include <linux/cache.h>
#include <linux/compiler.h>
/*
#include <linux/kfence.h>
#include <linux/module.h>
*/
#include <linux/cpu.h>
#include <linux/uaccess.h>
/*
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/debugfs.h>
#include <linux/kasan.h>
#include <asm/cacheflush.h>
*/
#include <asm/tlbflush.h>
#include <asm/page.h>
//#include <linux/memcontrol.h>

#include "internal.h"

#include "slab.h"

/*
 * Set of flags that will prevent slab merging
 */
#define SLAB_NEVER_MERGE \
    (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | SLAB_TRACE | \
     SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | SLAB_FAILSLAB)

#define SLAB_MERGE_SAME \
    (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | SLAB_CACHE_DMA32 | SLAB_ACCOUNT)

/*
 * Merge control. If this is set then no merging of slab caches will occur.
 */
static bool slab_nomerge = false;

enum slab_state slab_state;
LIST_HEAD(slab_caches);

DEFINE_MUTEX(slab_mutex);

struct kmem_cache *
kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1] __ro_after_init =
{ /* initialization for https://bugs.llvm.org/show_bug.cgi?id=42570 */ };
EXPORT_SYMBOL(kmalloc_caches);

struct kmem_cache *kmem_cache;

/*
 * Conversion table for small slabs sizes / 8 to the index in the
 * kmalloc array. This is necessary for slabs < 192 since we have non power
 * of two cache sizes there. The size of larger slabs can be determined using
 * fls.
 */
static u8 size_index[24] __ro_after_init = {
    3,  /* 8 */
    4,  /* 16 */
    5,  /* 24 */
    5,  /* 32 */
    6,  /* 40 */
    6,  /* 48 */
    6,  /* 56 */
    6,  /* 64 */
    1,  /* 72 */
    1,  /* 80 */
    1,  /* 88 */
    1,  /* 96 */
    7,  /* 104 */
    7,  /* 112 */
    7,  /* 120 */
    7,  /* 128 */
    2,  /* 136 */
    2,  /* 144 */
    2,  /* 152 */
    2,  /* 160 */
    2,  /* 168 */
    2,  /* 176 */
    2,  /* 184 */
    2   /* 192 */
};

#define KMALLOC_CGROUP_NAME(sz)
#define KMALLOC_DMA_NAME(sz)

#define INIT_KMALLOC_INFO(__size, __short_size)         \
{                               \
    .name[KMALLOC_NORMAL]  = "kmalloc-" #__short_size,  \
    .name[KMALLOC_RECLAIM] = "kmalloc-rcl-" #__short_size,  \
    KMALLOC_CGROUP_NAME(__short_size)           \
    KMALLOC_DMA_NAME(__short_size)              \
    .size = __size,                     \
}

/*
 * kmalloc_info[] is to make slub_debug=,kmalloc-xx option work at boot time.
 * kmalloc_index() supports up to 2^25=32MB, so the final entry of the table is
 * kmalloc-32M.
 */
const struct kmalloc_info_struct kmalloc_info[] __initconst = {
    INIT_KMALLOC_INFO(0, 0),
    INIT_KMALLOC_INFO(96, 96),
    INIT_KMALLOC_INFO(192, 192),
    INIT_KMALLOC_INFO(8, 8),
    INIT_KMALLOC_INFO(16, 16),
    INIT_KMALLOC_INFO(32, 32),
    INIT_KMALLOC_INFO(64, 64),
    INIT_KMALLOC_INFO(128, 128),
    INIT_KMALLOC_INFO(256, 256),
    INIT_KMALLOC_INFO(512, 512),
    INIT_KMALLOC_INFO(1024, 1k),
    INIT_KMALLOC_INFO(2048, 2k),
    INIT_KMALLOC_INFO(4096, 4k),
    INIT_KMALLOC_INFO(8192, 8k),
    INIT_KMALLOC_INFO(16384, 16k),
    INIT_KMALLOC_INFO(32768, 32k),
    INIT_KMALLOC_INFO(65536, 64k),
    INIT_KMALLOC_INFO(131072, 128k),
    INIT_KMALLOC_INFO(262144, 256k),
    INIT_KMALLOC_INFO(524288, 512k),
    INIT_KMALLOC_INFO(1048576, 1M),
    INIT_KMALLOC_INFO(2097152, 2M),
    INIT_KMALLOC_INFO(4194304, 4M),
    INIT_KMALLOC_INFO(8388608, 8M),
    INIT_KMALLOC_INFO(16777216, 16M),
    INIT_KMALLOC_INFO(33554432, 32M)
};

gfp_t kmalloc_fix_flags(gfp_t flags)
{
    gfp_t invalid_mask = flags & GFP_SLAB_BUG_MASK;

    flags &= ~GFP_SLAB_BUG_MASK;
    pr_warn("Unexpected gfp: %#x (%pGg). Fixing up to gfp: %#x (%pGg). Fix your code!\n",
            invalid_mask, &invalid_mask, flags, &flags);
    //dump_stack();

    return flags;
}

/*
 * To avoid unnecessary overhead, we pass through large allocation requests
 * directly to the page allocator. We use __GFP_COMP, because we will need to
 * know the allocation order to free the pages properly in kfree.
 */
void *kmalloc_order(size_t size, gfp_t flags, unsigned int order)
{
    void *ret = NULL;
    struct page *page;

    if (unlikely(flags & GFP_SLAB_BUG_MASK))
        flags = kmalloc_fix_flags(flags);

    flags |= __GFP_COMP;
    page = alloc_pages(flags, order);
    if (likely(page)) {
        ret = page_address(page);
        mod_lruvec_page_state(page, NR_SLAB_UNRECLAIMABLE_B,
                              PAGE_SIZE << order);
    }
    return ret;
}
EXPORT_SYMBOL(kmalloc_order);

/**
 * kfree - free previously allocated memory
 * @objp: pointer returned by kmalloc.
 *
 * If @objp is NULL, no operation is performed.
 *
 * Don't free memory not originally allocated by kmalloc()
 * or you will run into trouble.
 */
void kfree(const void *objp)
{
#if 0
    struct kmem_cache *c;
    unsigned long flags;

    trace_kfree(_RET_IP_, objp);

    if (unlikely(ZERO_OR_NULL_PTR(objp)))
        return;
    local_irq_save(flags);
    kfree_debugcheck(objp);
    c = virt_to_cache(objp);
    if (!c) {
        local_irq_restore(flags);
        return;
    }
    debug_check_no_locks_freed(objp, c->object_size);

    debug_check_no_obj_freed(objp, c->object_size);
    __cache_free(c, (void *)objp, _RET_IP_);
    local_irq_restore(flags);
#endif
}
EXPORT_SYMBOL(kfree);

/*
 * Figure out what the alignment of the objects will be given a set of
 * flags, a user specified alignment and the size of the objects.
 */
static unsigned int
calculate_alignment(slab_flags_t flags, unsigned int align, unsigned int size)
{
    /*
     * If the user wants hardware cache aligned objects then follow that
     * suggestion if the object is sufficiently large.
     *
     * The hardware cache alignment cannot override the specified
     * alignment though. If that is greater then use it.
     */
    if (flags & SLAB_HWCACHE_ALIGN) {
        unsigned int ralign;

        ralign = cache_line_size();
        while (size <= ralign / 2)
            ralign /= 2;
        align = max(align, ralign);
    }

    if (align < ARCH_SLAB_MINALIGN)
        align = ARCH_SLAB_MINALIGN;

    return ALIGN(align, sizeof(void *));
}

/* Create a cache during boot when no slab services are available yet */
void __init create_boot_cache(struct kmem_cache *s, const char *name,
                              unsigned int size, slab_flags_t flags,
                              unsigned int useroffset, unsigned int usersize)
{
    int err;
    unsigned int align = ARCH_KMALLOC_MINALIGN;

    s->name = name;
    s->size = s->object_size = size;

    /*
     * For power of two sizes, guarantee natural alignment for kmalloc
     * caches, regardless of SL*B debugging options.
     */
    if (is_power_of_2(size))
        align = max(align, size);
    s->align = calculate_alignment(flags, align, size);

    s->useroffset = useroffset;
    s->usersize = usersize;

    err = __kmem_cache_create(s, flags);
    if (err)
        panic("Creation of kmalloc slab %s size=%u failed. Reason %d\n",
              name, size, err);

    s->refcount = -1;   /* Exempt from merging for now */
}

bool slab_is_available(void)
{
    return slab_state >= UP;
}

static inline unsigned int size_index_elem(unsigned int bytes)
{
    return (bytes - 1) / 8;
}

/*
 * Find the kmem_cache structure that serves a given size of
 * allocation
 */
struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags)
{
    unsigned int index;

    if (size <= 192) {
        if (!size)
            return ZERO_SIZE_PTR;

        index = size_index[size_index_elem(size)];
    } else {
        if (WARN_ON_ONCE(size > KMALLOC_MAX_CACHE_SIZE))
            return NULL;
        index = fls(size - 1);
    }

    return kmalloc_caches[kmalloc_type(flags)][index];
}

struct kmem_cache *__init
create_kmalloc_cache(const char *name, unsigned int size, slab_flags_t flags,
                     unsigned int useroffset, unsigned int usersize)
{
    struct kmem_cache *s = kmem_cache_zalloc(kmem_cache, GFP_NOWAIT);

    if (!s)
        panic("Out of memory when creating slab %s\n", name);

    create_boot_cache(s, name, size, flags, useroffset, usersize);
    list_add(&s->list, &slab_caches);
    s->refcount = 1;
    return s;
}

/*
 * Patch up the size_index table if we have strange large alignment
 * requirements for the kmalloc array. This is only the case for
 * MIPS it seems. The standard arches will not generate any code here.
 *
 * Largest permitted alignment is 256 bytes due to the way we
 * handle the index determination for the smaller caches.
 *
 * Make sure that nothing crazy happens if someone starts tinkering
 * around with ARCH_KMALLOC_MINALIGN
 */
void __init setup_kmalloc_cache_index_table(void)
{
    unsigned int i;

    BUILD_BUG_ON(KMALLOC_MIN_SIZE > 256 || !is_power_of_2(KMALLOC_MIN_SIZE));

    for (i = 8; i < KMALLOC_MIN_SIZE; i += 8) {
        unsigned int elem = size_index_elem(i);

        if (elem >= ARRAY_SIZE(size_index))
            break;
        size_index[elem] = KMALLOC_SHIFT_LOW;
    }

    if (KMALLOC_MIN_SIZE >= 64) {
        /*
         * The 96 byte sized cache is not used if the alignment
         * is 64 byte.
         */
        for (i = 64 + 8; i <= 96; i += 8)
            size_index[size_index_elem(i)] = 7;

    }

    if (KMALLOC_MIN_SIZE >= 128) {
        /*
         * The 192 byte sized cache is not used if the alignment
         * is 128 byte. Redirect kmalloc to use the 256 byte cache
         * instead.
         */
        for (i = 128 + 8; i <= 192; i += 8)
            size_index[size_index_elem(i)] = 8;
    }
}

static void __init
new_kmalloc_cache(int idx, enum kmalloc_cache_type type, slab_flags_t flags)
{
    if (type == KMALLOC_RECLAIM) {
        flags |= SLAB_RECLAIM_ACCOUNT;
    }

    kmalloc_caches[type][idx] =
        create_kmalloc_cache(kmalloc_info[idx].name[type],
                             kmalloc_info[idx].size, flags, 0,
                             kmalloc_info[idx].size);
}

/*
 * Create the kmalloc array. Some of the regular kmalloc arrays
 * may already have been created because they were needed to
 * enable allocations for slab creation.
 */
void __init create_kmalloc_caches(slab_flags_t flags)
{
    int i;
    enum kmalloc_cache_type type;

    /*
     * Including KMALLOC_CGROUP if CONFIG_MEMCG_KMEM defined
     */
    for (type = KMALLOC_NORMAL; type <= KMALLOC_RECLAIM; type++) {
        for (i = KMALLOC_SHIFT_LOW; i <= KMALLOC_SHIFT_HIGH; i++) {
            if (!kmalloc_caches[type][i])
                new_kmalloc_cache(i, type, flags);

            /*
             * Caches that are not of the two-to-the-power-of size.
             * These have to be created immediately after the
             * earlier power of two caches
             */
            if (KMALLOC_MIN_SIZE <= 32 && i == 6 && !kmalloc_caches[type][1])
                new_kmalloc_cache(1, type, flags);
            if (KMALLOC_MIN_SIZE <= 64 && i == 7 && !kmalloc_caches[type][2])
                new_kmalloc_cache(2, type, flags);
        }
    }

    /* Kmalloc array is now usable */
    slab_state = UP;
}

static struct kmem_cache *
create_cache(const char *name, unsigned int object_size, unsigned int align,
             slab_flags_t flags, unsigned int useroffset,
             unsigned int usersize, void (*ctor)(void *),
             struct kmem_cache *root_cache)
{
    int err;
    struct kmem_cache *s;

    if (WARN_ON(useroffset + usersize > object_size))
        useroffset = usersize = 0;

    err = -ENOMEM;
    s = kmem_cache_zalloc(kmem_cache, GFP_KERNEL);
    if (!s)
        goto out;

    s->name = name;
    s->size = s->object_size = object_size;
    s->align = align;
    s->ctor = ctor;
    s->useroffset = useroffset;
    s->usersize = usersize;

    err = __kmem_cache_create(s, flags);
    if (err)
        goto out_free_cache;

    s->refcount = 1;
    list_add(&s->list, &slab_caches);

 out:
    if (err)
        return ERR_PTR(err);
    return s;

 out_free_cache:
    kmem_cache_free(kmem_cache, s);
    goto out;
}

static inline int kmem_cache_sanity_check(const char *name, unsigned int size)
{
    return 0;
}

/**
 * kmem_cache_create_usercopy - Create a cache with a region suitable
 * for copying to userspace
 * @name: A string which is used in /proc/slabinfo to identify this cache.
 * @size: The size of objects to be created in this cache.
 * @align: The required alignment for the objects.
 * @flags: SLAB flags
 * @useroffset: Usercopy region offset
 * @usersize: Usercopy region size
 * @ctor: A constructor for the objects.
 *
 * Cannot be called within a interrupt, but can be interrupted.
 * The @ctor is run when new pages are allocated by the cache.
 *
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialised memory.
 *
 * %SLAB_RED_ZONE - Insert `Red` zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline.  This can be beneficial if you're counting cycles as closely
 * as davem.
 *
 * Return: a pointer to the cache on success, NULL on failure.
 */
struct kmem_cache *
kmem_cache_create_usercopy(const char *name, unsigned int size,
                           unsigned int align, slab_flags_t flags,
                           unsigned int useroffset, unsigned int usersize,
                           void (*ctor)(void *))
{
    int err;
    const char *cache_name;
    struct kmem_cache *s = NULL;

    mutex_lock(&slab_mutex);

    err = kmem_cache_sanity_check(name, size);
    if (err) {
        goto out_unlock;
    }

    /* Refuse requests with allocator specific flags */
    if (flags & ~SLAB_FLAGS_PERMITTED) {
        err = -EINVAL;
        goto out_unlock;
    }

    /*
     * Some allocators will constraint the set of valid flags to a subset
     * of all flags. We expect them to define CACHE_CREATE_MASK in this
     * case, and we'll just provide them with a sanitized version of the
     * passed flags.
     */
    flags &= CACHE_CREATE_MASK;

    /* Fail closed on bad usersize of useroffset values. */
    if (WARN_ON(!usersize && useroffset) ||
        WARN_ON(size < usersize || size - usersize < useroffset))
        usersize = useroffset = 0;

    if (!usersize)
        s = __kmem_cache_alias(name, size, align, flags, ctor);
    if (s)
        goto out_unlock;

    cache_name = kstrdup_const(name, GFP_KERNEL);
    if (!cache_name) {
        err = -ENOMEM;
        goto out_unlock;
    }

    s = create_cache(cache_name, size, calculate_alignment(flags, align, size),
                     flags, useroffset, usersize, ctor, NULL);
    if (IS_ERR(s)) {
        err = PTR_ERR(s);
        kfree_const(cache_name);
    }

 out_unlock:
    mutex_unlock(&slab_mutex);

    if (err) {
        if (flags & SLAB_PANIC)
            panic("%s: Failed to create slab '%s'. Error %d\n",
                  __func__, name, err);
        else {
            pr_warn("%s(%s) failed with error %d\n", __func__, name, err);
            //dump_stack();
        }
        return NULL;
    }
    return s;
}
EXPORT_SYMBOL(kmem_cache_create_usercopy);

struct kmem_cache *
find_mergeable(unsigned int size, unsigned int align, slab_flags_t flags,
               const char *name, void (*ctor)(void *))
{
    struct kmem_cache *s;

    if (slab_nomerge)
        return NULL;

    if (ctor)
        return NULL;

    size = ALIGN(size, sizeof(void *));
    align = calculate_alignment(flags, align, size);
    size = ALIGN(size, align);
    flags = kmem_cache_flags(size, flags, name);

    if (flags & SLAB_NEVER_MERGE)
        return NULL;

    list_for_each_entry_reverse(s, &slab_caches, list) {
        if (slab_unmergeable(s))
            continue;

        if (size > s->size)
            continue;

        if ((flags & SLAB_MERGE_SAME) != (s->flags & SLAB_MERGE_SAME))
            continue;
        /*
         * Check if alignment is compatible.
         * Courtesy of Adrian Drzewiecki
         */
        if ((s->size & ~(align - 1)) != s->size)
            continue;

        if (s->size - size >= sizeof(void *))
            continue;

        if (align && (align > s->align || s->align % align))
            continue;

        return s;
    }
    return NULL;
}

/*
 * Find a mergeable slab cache
 */
int slab_unmergeable(struct kmem_cache *s)
{
    if (slab_nomerge || (s->flags & SLAB_NEVER_MERGE))
        return 1;

    if (s->ctor)
        return 1;

    if (s->usersize)
        return 1;

    /*
     * We may have set a slab to be unmergeable during bootstrap.
     */
    if (s->refcount < 0)
        return 1;

    return 0;
}

/**
 * kmem_cache_create - Create a cache.
 * @name: A string which is used in /proc/slabinfo to identify this cache.
 * @size: The size of objects to be created in this cache.
 * @align: The required alignment for the objects.
 * @flags: SLAB flags
 * @ctor: A constructor for the objects.
 *
 * Cannot be called within a interrupt, but can be interrupted.
 * The @ctor is run when new pages are allocated by the cache.
 *
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialised memory.
 *
 * %SLAB_RED_ZONE - Insert `Red` zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline.  This can be beneficial if you're counting cycles as closely
 * as davem.
 *
 * Return: a pointer to the cache on success, NULL on failure.
 */
struct kmem_cache *
kmem_cache_create(const char *name, unsigned int size, unsigned int align,
                  slab_flags_t flags, void (*ctor)(void *))
{
    return kmem_cache_create_usercopy(name, size, align, flags, 0, 0, ctor);
}
EXPORT_SYMBOL(kmem_cache_create);

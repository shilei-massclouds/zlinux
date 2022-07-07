// SPDX-License-Identifier: GPL-2.0
/*
 * drivers/base/devres.c - device resource management
 *
 * Copyright (c) 2006  SUSE Linux Products GmbH
 * Copyright (c) 2006  Tejun Heo <teheo@suse.de>
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/percpu.h>

#include <asm/sections.h>

#include "base.h"

struct devres_node {
    struct list_head    entry;
    dr_release_t        release;
    const char          *name;
    size_t              size;
};

struct devres {
    struct devres_node      node;
    /*
     * Some archs want to perform DMA into kmalloc caches
     * and need a guaranteed alignment larger than
     * the alignment of a 64-bit integer.
     * Thus we use ARCH_KMALLOC_MINALIGN here and get exactly the same
     * buffer alignment as if it was allocated by plain kmalloc().
     */
    u8 __aligned(ARCH_KMALLOC_MINALIGN) data[];
};

static void devres_log(struct device *dev, struct devres_node *node,
                       const char *op)
{
}

/*
 * Managed kmalloc/kfree
 */
static void devm_kmalloc_release(struct device *dev, void *res)
{
    /* noop */
}

static int devm_kmalloc_match(struct device *dev, void *res, void *data)
{
    return res == data;
}

static bool check_dr_size(size_t size, size_t *tot_size)
{
    /* We must catch any near-SIZE_MAX cases that could overflow. */
    if (unlikely(check_add_overflow(sizeof(struct devres), size, tot_size)))
        return false;

    return true;
}

static __always_inline struct devres *
alloc_dr(dr_release_t release, size_t size, gfp_t gfp, int nid)
{
    size_t tot_size;
    struct devres *dr;

    if (!check_dr_size(size, &tot_size))
        return NULL;

    dr = kmalloc_node_track_caller(tot_size, gfp, nid);
    if (unlikely(!dr))
        return NULL;

    memset(dr, 0, offsetof(struct devres, data));

    INIT_LIST_HEAD(&dr->node.entry);
    dr->node.release = release;
    return dr;
}

static void
set_node_dbginfo(struct devres_node *node, const char *name, size_t size)
{
    node->name = name;
    node->size = size;
}

static void add_dr(struct device *dev, struct devres_node *node)
{
    devres_log(dev, node, "ADD");
    BUG_ON(!list_empty(&node->entry));
    list_add_tail(&node->entry, &dev->devres_head);
}

/**
 * devres_free - Free device resource data
 * @res: Pointer to devres data to free
 *
 * Free devres created with devres_alloc().
 */
void devres_free(void *res)
{
    if (res) {
        struct devres *dr = container_of(res, struct devres, data);

        BUG_ON(!list_empty(&dr->node.entry));
        kfree(dr);
    }
}
EXPORT_SYMBOL_GPL(devres_free);

/**
 * devres_add - Register device resource
 * @dev: Device to add resource to
 * @res: Resource to register
 *
 * Register devres @res to @dev.  @res should have been allocated
 * using devres_alloc().  On driver detach, the associated release
 * function will be invoked and devres will be freed automatically.
 */
void devres_add(struct device *dev, void *res)
{
    struct devres *dr = container_of(res, struct devres, data);
    unsigned long flags;

    spin_lock_irqsave(&dev->devres_lock, flags);
    add_dr(dev, &dr->node);
    spin_unlock_irqrestore(&dev->devres_lock, flags);
}
EXPORT_SYMBOL_GPL(devres_add);

/**
 * devm_kmalloc - Resource-managed kmalloc
 * @dev: Device to allocate memory for
 * @size: Allocation size
 * @gfp: Allocation gfp flags
 *
 * Managed kmalloc.  Memory allocated with this function is
 * automatically freed on driver detach.  Like all other devres
 * resources, guaranteed alignment is unsigned long long.
 *
 * RETURNS:
 * Pointer to allocated memory on success, NULL on failure.
 */
void *devm_kmalloc(struct device *dev, size_t size, gfp_t gfp)
{
    struct devres *dr;

    if (unlikely(!size))
        return ZERO_SIZE_PTR;

    /* use raw alloc_dr for kmalloc caller tracing */
    dr = alloc_dr(devm_kmalloc_release, size, gfp, dev_to_node(dev));
    if (unlikely(!dr))
        return NULL;

    /*
     * This is named devm_kzalloc_release for historical reasons
     * The initial implementation did not support kmalloc, only kzalloc
     */
    set_node_dbginfo(&dr->node, "devm_kzalloc_release", size);
    devres_add(dev, dr->data);
    return dr->data;
}
EXPORT_SYMBOL_GPL(devm_kmalloc);

/**
 * devm_kfree - Resource-managed kfree
 * @dev: Device this memory belongs to
 * @p: Memory to free
 *
 * Free memory allocated with devm_kmalloc().
 */
void devm_kfree(struct device *dev, const void *p)
{
    int rc;

    /*
     * Special cases: pointer to a string in .rodata returned by
     * devm_kstrdup_const() or NULL/ZERO ptr.
     */
    if (unlikely(is_kernel_rodata((unsigned long)p) || ZERO_OR_NULL_PTR(p)))
        return;

    panic("%s: END!\n", __func__);
#if 0
    rc = devres_destroy(dev, devm_kmalloc_release,
                        devm_kmalloc_match, (void *)p);
    WARN_ON(rc);
#endif
}
EXPORT_SYMBOL_GPL(devm_kfree);

/**
 * devm_kstrdup - Allocate resource managed space and
 *                copy an existing string into that.
 * @dev: Device to allocate memory for
 * @s: the string to duplicate
 * @gfp: the GFP mask used in the devm_kmalloc() call when
 *       allocating memory
 * RETURNS:
 * Pointer to allocated string on success, NULL on failure.
 */
char *devm_kstrdup(struct device *dev, const char *s, gfp_t gfp)
{
    size_t size;
    char *buf;

    if (!s)
        return NULL;

    size = strlen(s) + 1;
    buf = devm_kmalloc(dev, size, gfp);
    if (buf)
        memcpy(buf, s, size);
    return buf;
}
EXPORT_SYMBOL_GPL(devm_kstrdup);

/**
 * devm_kvasprintf - Allocate resource managed space and format a string
 *           into that.
 * @dev: Device to allocate memory for
 * @gfp: the GFP mask used in the devm_kmalloc() call when
 *       allocating memory
 * @fmt: The printf()-style format string
 * @ap: Arguments for the format string
 * RETURNS:
 * Pointer to allocated string on success, NULL on failure.
 */
char *devm_kvasprintf(struct device *dev, gfp_t gfp, const char *fmt,
                      va_list ap)
{
    unsigned int len;
    char *p;
    va_list aq;

    va_copy(aq, ap);
    len = vsnprintf(NULL, 0, fmt, aq);
    va_end(aq);

    p = devm_kmalloc(dev, len+1, gfp);
    if (!p)
        return NULL;

    vsnprintf(p, len+1, fmt, ap);

    return p;
}
EXPORT_SYMBOL(devm_kvasprintf);

/**
 * devm_kasprintf - Allocate resource managed space and format a string
 *          into that.
 * @dev: Device to allocate memory for
 * @gfp: the GFP mask used in the devm_kmalloc() call when
 *       allocating memory
 * @fmt: The printf()-style format string
 * @...: Arguments for the format string
 * RETURNS:
 * Pointer to allocated string on success, NULL on failure.
 */
char *devm_kasprintf(struct device *dev, gfp_t gfp, const char *fmt, ...)
{
    va_list ap;
    char *p;

    va_start(ap, fmt);
    p = devm_kvasprintf(dev, gfp, fmt, ap);
    va_end(ap);

    return p;
}
EXPORT_SYMBOL_GPL(devm_kasprintf);

/**
 * __devres_alloc_node - Allocate device resource data
 * @release: Release function devres will be associated with
 * @size: Allocation size
 * @gfp: Allocation flags
 * @nid: NUMA node
 * @name: Name of the resource
 *
 * Allocate devres of @size bytes.  The allocated area is zeroed, then
 * associated with @release.  The returned pointer can be passed to
 * other devres_*() functions.
 *
 * RETURNS:
 * Pointer to allocated devres on success, NULL on failure.
 */
void *__devres_alloc_node(dr_release_t release, size_t size, gfp_t gfp, int nid,
                          const char *name)
{
    struct devres *dr;

    dr = alloc_dr(release, size, gfp | __GFP_ZERO, nid);
    if (unlikely(!dr))
        return NULL;
    set_node_dbginfo(&dr->node, name, size);
    return dr->data;
}
EXPORT_SYMBOL_GPL(__devres_alloc_node);

/**
 * devres_destroy - Find a device resource and destroy it
 * @dev: Device to find resource from
 * @release: Look for resources associated with this release function
 * @match: Match function (optional)
 * @match_data: Data for the match function
 *
 * Find the latest devres of @dev associated with @release and for
 * which @match returns 1.  If @match is NULL, it's considered to
 * match all.  If found, the resource is removed atomically and freed.
 *
 * Note that the release function for the resource will not be called,
 * only the devres-allocated data will be freed.  The caller becomes
 * responsible for freeing any other data.
 *
 * RETURNS:
 * 0 if devres is found and freed, -ENOENT if not found.
 */
int devres_destroy(struct device *dev, dr_release_t release,
                   dr_match_t match, void *match_data)
{
#if 0
    void *res;

    res = devres_remove(dev, release, match, match_data);
    if (unlikely(!res))
        return -ENOENT;

    devres_free(res);
#endif
    panic("%s: END!\n", __func__);
    return 0;
}
EXPORT_SYMBOL_GPL(devres_destroy);

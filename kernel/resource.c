// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/kernel/resource.c
 *
 * Copyright (C) 1999   Linus Torvalds
 * Copyright (C) 1999   Martin Mares <mj@ucw.cz>
 *
 * Arbitrary resource management.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/export.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#if 0
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/pseudo_fs.h>
#endif
#include <linux/sched.h>
#if 0
#include <linux/seq_file.h>
#endif
#include <linux/device.h>
#include <linux/pfn.h>
#include <linux/mm.h>
#if 0
#include <linux/mount.h>
#include <linux/resource_ext.h>
#endif
#include <uapi/linux/magic.h>
#include <asm/io.h>

struct region_devres {
    struct resource *parent;
    resource_size_t start;
    resource_size_t n;
};

struct resource iomem_resource = {
    .name   = "PCI mem",
    .start  = 0,
    .end    = -1,
    .flags  = IORESOURCE_MEM,
};
EXPORT_SYMBOL(iomem_resource);

static DEFINE_RWLOCK(resource_lock);

/**
 * __release_region - release a previously reserved resource region
 * @parent: parent resource descriptor
 * @start: resource start address
 * @n: resource region size
 *
 * The described resource region must match a currently busy region.
 */
void __release_region(struct resource *parent,
                      resource_size_t start, resource_size_t n)
{
    panic("%s: END!\n", __func__);
}

static void devm_region_release(struct device *dev, void *res)
{
    struct region_devres *this = res;

    __release_region(this->parent, this->start, this->n);
}

static void free_resource(struct resource *res)
{
    /**
     * If the resource was allocated using memblock early during boot
     * we'll leak it here: we can only return full pages back to the
     * buddy and trying to be smart and reusing them eventually in
     * alloc_resource() overcomplicates resource handling.
     */
    if (res && PageSlab(virt_to_head_page(res)))
        kfree(res);
}

static struct resource *alloc_resource(gfp_t flags)
{
    return kzalloc(sizeof(struct resource), flags);
}

/**
 * __request_region - create a new busy resource region
 * @parent: parent resource descriptor
 * @start: resource start address
 * @n: resource region size
 * @name: reserving caller's ID string
 * @flags: IO resource flags
 */
struct resource *__request_region(struct resource *parent,
                                  resource_size_t start, resource_size_t n,
                                  const char *name, int flags)
{
    struct resource *res = alloc_resource(GFP_KERNEL);
    int ret;

    if (!res)
        return NULL;

    panic("%s: END!\n", __func__);
#if 0
    write_lock(&resource_lock);
    ret = __request_region_locked(res, parent, start, n, name, flags);
    write_unlock(&resource_lock);

    if (ret) {
        free_resource(res);
        return NULL;
    }

    if (parent == &iomem_resource)
        revoke_iomem(res);

    return res;
#endif
}
EXPORT_SYMBOL(__request_region);

struct resource *
__devm_request_region(struct device *dev, struct resource *parent,
                      resource_size_t start, resource_size_t n,
                      const char *name)
{
    struct region_devres *dr = NULL;
    struct resource *res;

    dr = devres_alloc(devm_region_release, sizeof(struct region_devres),
                      GFP_KERNEL);
    if (!dr)
        return NULL;

    dr->parent = parent;
    dr->start = start;
    dr->n = n;

    res = __request_region(parent, start, n, name, 0);
    if (res)
        devres_add(dev, dr);
    else
        devres_free(dr);

    return res;
}
EXPORT_SYMBOL(__devm_request_region);

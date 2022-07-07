// SPDX-License-Identifier: GPL-2.0
/*
 * device.h - generic, centralized driver model
 *
 * Copyright (c) 2001-2003 Patrick Mochel <mochel@osdl.org>
 * Copyright (c) 2004-2009 Greg Kroah-Hartman <gregkh@suse.de>
 * Copyright (c) 2008-2009 Novell Inc.
 *
 * See Documentation/driver-api/driver-model/ for more information.
 */

#ifndef _DEVICE_H_
#define _DEVICE_H_

#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/ioport.h>
#include <linux/compiler.h>
#if 0
#include <linux/dev_printk.h>
#include <linux/energy_model.h>
#endif
#include <linux/klist.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/gfp.h>
#include <linux/device/bus.h>
#include <linux/pm.h>
#include <linux/device/driver.h>
#if 0
#include <linux/uidgid.h>
#include <linux/overflow.h>
#include <linux/device/class.h>
#include <asm/device.h>
#endif

/**
 * enum dl_dev_state - Device driver presence tracking information.
 * @DL_DEV_NO_DRIVER: There is no driver attached to the device.
 * @DL_DEV_PROBING: A driver is probing.
 * @DL_DEV_DRIVER_BOUND: The driver has been bound to the device.
 * @DL_DEV_UNBINDING: The driver is unbinding from the device.
 */
enum dl_dev_state {
    DL_DEV_NO_DRIVER = 0,
    DL_DEV_PROBING,
    DL_DEV_DRIVER_BOUND,
    DL_DEV_UNBINDING,
};

/*
 * The type of device, "struct device" is embedded in. A class
 * or bus can contain devices of different types
 * like "partitions" and "disks", "mouse" and "event".
 * This identifies the device type and carries type-specific
 * information, equivalent to the kobj_type of a kobject.
 * If "name" is specified, the uevent will contain it in
 * the DEVTYPE variable.
 */
struct device_type {
    const char *name;
#if 0
    const struct attribute_group **groups;
    int (*uevent)(struct device *dev, struct kobj_uevent_env *env);
    char *(*devnode)(struct device *dev, umode_t *mode,
                     kuid_t *uid, kgid_t *gid);
    void (*release)(struct device *dev);
#endif
    const struct dev_pm_ops *pm;
};

struct device {
    struct kobject  kobj;
    struct device   *parent;

    struct device_private *p;

    const char *init_name;              /* initial name of the device */
    const struct device_type *type;

    struct bus_type *bus;               /* type of bus device is on */

    struct device_driver *driver;       /* which driver has allocated this
                                           device */

    void *platform_data;                /* Platform specific data,
                                           device core doesn't touch it */

    void *driver_data;                  /* Driver data, set and get with
                                           dev_set_drvdata/dev_get_drvdata */

    struct mutex mutex;                 /* mutex to synchronize calls to
                                           its driver. */

#if 0
    struct dev_links_info   links;
#endif

    const struct dma_map_ops *dma_ops;

    u64 *dma_mask;          /* dma mask (if dma'able device) */
    u64 coherent_dma_mask;  /* Like dma_mask, but for alloc_coherent mappings
                               as not all hardware supports 64 bit addresses
                               for consistent allocations such descriptors. */
    u64 bus_dma_limit;      /* upstream dma constraint */
    const struct bus_dma_region *dma_range_map;

    struct device_dma_parameters *dma_parms;

    struct list_head dma_pools;         /* dma pools (if dma'ble) */

    struct dma_coherent_mem *dma_mem;   /* internal for coherent mem override */

    struct device_node      *of_node;   /* associated device tree node */
    struct fwnode_handle    *fwnode;    /* firmware device node */

    u32 id;     /* device instance */

    spinlock_t          devres_lock;
    struct list_head    devres_head;

    struct class *class;

    void (*release)(struct device *dev);

    struct dev_iommu    *iommu;

    bool offline_disabled:1;
    bool offline:1;
    bool of_node_reused:1;
    bool state_synced:1;
    bool can_match:1;
};

/*
 * High level routines for use by the bus drivers
 */
int __must_check device_register(struct device *dev);
void device_unregister(struct device *dev);
void device_initialize(struct device *dev);

__printf(2, 3) int dev_set_name(struct device *dev, const char *name, ...);

static inline const char *dev_name(const struct device *dev)
{
    /* Use the init name until the kobject becomes available */
    if (dev->init_name)
        return dev->init_name;

    return kobject_name(&dev->kobj);
}

int __must_check device_add(struct device *dev);

/*
 * get_device - atomically increment the reference count for the device.
 *
 */
struct device *get_device(struct device *dev);
void put_device(struct device *dev);

static inline struct device *kobj_to_dev(struct kobject *kobj)
{
    return container_of(kobj, struct device, kobj);
}

static inline void *dev_get_drvdata(const struct device *dev)
{
    return dev->driver_data;
}

static inline void dev_set_drvdata(struct device *dev, void *data)
{
    dev->driver_data = data;
}

static inline void device_lock(struct device *dev)
{
    mutex_lock(&dev->mutex);
}

static inline void device_unlock(struct device *dev)
{
    mutex_unlock(&dev->mutex);
}

int __must_check driver_attach(struct device_driver *drv);

static inline int device_is_registered(struct device *dev)
{
    return dev->kobj.state_in_sysfs;
}

/* managed devm_k.alloc/kfree for device drivers */
void *devm_kmalloc(struct device *dev, size_t size, gfp_t gfp) __malloc;

static inline void *devm_kzalloc(struct device *dev, size_t size, gfp_t gfp)
{
    return devm_kmalloc(dev, size, gfp | __GFP_ZERO);
}

void devm_kfree(struct device *dev, const void *p);

static inline int dev_to_node(struct device *dev)
{
    return NUMA_NO_NODE;
}

static inline void set_dev_node(struct device *dev, int node)
{
}

/* device resource management */
typedef void (*dr_release_t)(struct device *dev, void *res);
typedef int (*dr_match_t)(struct device *dev, void *res, void *match_data);

void __iomem *devm_ioremap_resource(struct device *dev,
                                    const struct resource *res);

void __iomem *devm_ioremap_resource_wc(struct device *dev,
                                       const struct resource *res);

char *devm_kstrdup(struct device *dev, const char *s, gfp_t gfp) __malloc;

__printf(3, 0) char *devm_kvasprintf(struct device *dev, gfp_t gfp,
                                     const char *fmt, va_list ap) __malloc;

__printf(3, 4) char *devm_kasprintf(struct device *dev, gfp_t gfp,
                                    const char *fmt, ...) __malloc;

void devres_free(void *res);
void devres_add(struct device *dev, void *res);

void *__devres_alloc_node(dr_release_t release, size_t size, gfp_t gfp,
                          int nid, const char *name) __malloc;

#define devres_alloc(release, size, gfp) \
    __devres_alloc_node(release, size, gfp, NUMA_NO_NODE, #release)
#define devres_alloc_node(release, size, gfp, nid) \
    __devres_alloc_node(release, size, gfp, nid, #release)

void *devres_remove(struct device *dev, dr_release_t release,
                    dr_match_t match, void *match_data);
int devres_destroy(struct device *dev, dr_release_t release,
                   dr_match_t match, void *match_data);
int devres_release(struct device *dev, dr_release_t release,
                   dr_match_t match, void *match_data);

#endif /* _DEVICE_H_ */

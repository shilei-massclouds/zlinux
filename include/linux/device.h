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
#include <linux/dev_printk.h>
#if 0
#include <linux/energy_model.h>
#endif
#include <linux/klist.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/gfp.h>
#include <linux/device/bus.h>
#include <linux/device/class.h>
#include <linux/device/driver.h>
#include <linux/pm.h>
#include <linux/uidgid.h>
#if 0
#include <linux/overflow.h>
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

struct device_dma_parameters {
    /*
     * a low level driver may set these to teach IOMMU code about
     * sg limitations.
     */
    unsigned int max_segment_size;
    unsigned int min_align_mask;
    unsigned long segment_boundary_mask;
};

/**
 * struct device - The basic device structure
 * @parent: The device's "parent" device, the device to which it is attached.
 *      In most cases, a parent device is some sort of bus or host
 *      controller. If parent is NULL, the device, is a top-level device,
 *      which is not usually what you want.
 * @p:      Holds the private data of the driver core portions of the device.
 *      See the comment of the struct device_private for detail.
 * @kobj:   A top-level, abstract class from which other classes are derived.
 * @init_name:  Initial name of the device.
 * @type:   The type of device.
 *      This identifies the device type and carries type-specific
 *      information.
 * @mutex:  Mutex to synchronize calls to its driver.
 * @lockdep_mutex: An optional debug lock that a subsystem can use as a
 *      peer lock to gain localized lockdep coverage of the device_lock.
 * @bus:    Type of bus device is on.
 * @driver: Which driver has allocated this
 * @platform_data: Platform data specific to the device.
 *      Example: For devices on custom boards, as typical of embedded
 *      and SOC based hardware, Linux often uses platform_data to point
 *      to board-specific structures describing devices and how they
 *      are wired.  That can include what ports are available, chip
 *      variants, which GPIO pins act in what additional roles, and so
 *      on.  This shrinks the "Board Support Packages" (BSPs) and
 *      minimizes board-specific #ifdefs in drivers.
 * @driver_data: Private pointer for driver specific info.
 * @links:  Links to suppliers and consumers of this device.
 * @power:  For device power management.
 *      See Documentation/driver-api/pm/devices.rst for details.
 * @pm_domain:  Provide callbacks that are executed during system suspend,
 *      hibernation, system resume and during runtime PM transitions
 *      along with subsystem-level and driver-level callbacks.
 * @em_pd:  device's energy model performance domain
 * @pins:   For device pin management.
 *      See Documentation/driver-api/pin-control.rst for details.
 * @msi:    MSI related data
 * @numa_node:  NUMA node this device is close to.
 * @dma_ops:    DMA mapping operations for this device.
 * @dma_mask:   Dma mask (if dma'ble device).
 * @coherent_dma_mask: Like dma_mask, but for alloc_coherent mapping as not all
 *      hardware supports 64-bit addresses for consistent allocations
 *      such descriptors.
 * @bus_dma_limit: Limit of an upstream bridge or bus which imposes a smaller
 *      DMA limit than the device itself supports.
 * @dma_range_map: map for DMA memory ranges relative to that of RAM
 * @dma_parms:  A low level driver may set these to teach IOMMU code about
 *      segment limitations.
 * @dma_pools:  Dma pools (if dma'ble device).
 * @dma_mem:    Internal for coherent mem override.
 * @cma_area:   Contiguous memory area for dma allocations
 * @dma_io_tlb_mem: Pointer to the swiotlb pool used.  Not for driver use.
 * @archdata:   For arch-specific additions.
 * @of_node:    Associated device tree node.
 * @fwnode: Associated device node supplied by platform firmware.
 * @devt:   For creating the sysfs "dev".
 * @id:     device instance
 * @devres_lock: Spinlock to protect the resource of the device.
 * @devres_head: The resources list of the device.
 * @knode_class: The node used to add the device to the class list.
 * @class:  The class of the device.
 * @groups: Optional attribute groups.
 * @release:    Callback to free the device after all references have
 *      gone away. This should be set by the allocator of the
 *      device (i.e. the bus driver that discovered the device).
 * @iommu_group: IOMMU group the device belongs to.
 * @iommu:  Per device generic IOMMU runtime data
 * @removable:  Whether the device can be removed from the system. This
 *              should be set by the subsystem / bus driver that discovered
 *              the device.
 *
 * @offline_disabled: If set, the device is permanently online.
 * @offline:    Set after successful invocation of bus type's .offline().
 * @of_node_reused: Set if the device-tree node is shared with an ancestor
 *              device.
 * @state_synced: The hardware state of this device has been synced to match
 *        the software state of this device by calling the driver/bus
 *        sync_state() callback.
 * @can_match:  The device has matched with a driver at least once or it is in
 *      a bus (like AMBA) which can't check for matching drivers until
 *      other devices probe successfully.
 * @dma_coherent: this particular device is dma coherent, even if the
 *      architecture supports non-coherent devices.
 * @dma_ops_bypass: If set to %true then the dma_ops are bypassed for the
 *      streaming DMA operations (->map_* / ->unmap_* / ->sync_*),
 *      and optionall (if the coherent mask is large enough) also
 *      for dma allocations.  This flag is managed by the dma ops
 *      instance from ->dma_supported.
 *
 * At the lowest level, every device in a Linux system is represented by an
 * instance of struct device. The device structure contains the information
 * that the device model core needs to model the system. Most subsystems,
 * however, track additional information about the devices they host. As a
 * result, it is rare for devices to be represented by bare device structures;
 * instead, that structure, like kobject structures, is usually embedded within
 * a higher-level representation of the device.
 */
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

    dev_t   devt;   /* dev_t, creates the sysfs "dev" */
    u32     id;     /* device instance */

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

static inline struct device_node *dev_of_node(struct device *dev)
{
    return dev->of_node;
}

int  __must_check device_attach(struct device *dev);
int __must_check driver_attach(struct device_driver *drv);
void device_initial_probe(struct device *dev);

int dev_err_probe(const struct device *dev,
                  int err, const char *fmt, ...);

void device_del(struct device *dev);

#define sysfs_deprecated 0

/*
 * Easy functions for dynamically creating devices on the fly
 */
__printf(5, 6) struct device *
device_create(struct class *cls, struct device *parent, dev_t devt,
              void *drvdata, const char *fmt, ...);

static inline void dev_set_uevent_suppress(struct device *dev, int val)
{
    dev->kobj.uevent_suppress = val;
}

static inline void *dev_get_platdata(const struct device *dev)
{
    return dev->platform_data;
}

#endif /* _DEVICE_H_ */

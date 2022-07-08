/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VIRTIO_H
#define _LINUX_VIRTIO_H
/* Everything a virtio driver needs to work with any particular virtio
 * implementation. */
#include <linux/types.h>
#if 0
#include <linux/scatterlist.h>
#endif
#include <linux/spinlock.h>
#include <linux/device.h>
#include <linux/mod_devicetable.h>
#include <linux/gfp.h>

/**
 * virtqueue - a queue to register buffers for sending or receiving.
 * @list: the chain of virtqueues for this device
 * @callback: the function to call when buffers are consumed (can be NULL).
 * @name: the name of this virtqueue (mainly for debugging)
 * @vdev: the virtio device this queue was created for.
 * @priv: a pointer for the virtqueue implementation to use.
 * @index: the zero-based ordinal number for this queue.
 * @num_free: number of elements we expect to be able to fit.
 *
 * A note on @num_free: with indirect buffers, each buffer needs one
 * element in the queue, otherwise a buffer will need one element per
 * sg element.
 */
struct virtqueue {
    struct list_head list;
    void (*callback)(struct virtqueue *vq);
    const char *name;
    struct virtio_device *vdev;
    unsigned int index;
    unsigned int num_free;
    void *priv;
};

/**
 * virtio_device - representation of a device using virtio
 * @index: unique position on the virtio bus
 * @failed: saved value for VIRTIO_CONFIG_S_FAILED bit (for restore)
 * @config_enabled: configuration change reporting enabled
 * @config_change_pending: configuration change reported while disabled
 * @config_lock: protects configuration change reporting
 * @dev: underlying device.
 * @id: the device type identification (used to match it with a driver).
 * @config: the configuration ops for this device.
 * @vringh_config: configuration ops for host vrings.
 * @vqs: the list of virtqueues for this device.
 * @features: the features supported by both driver and device.
 * @priv: private pointer for the driver's use.
 */
struct virtio_device {
    int index;
    bool failed;
    bool config_enabled;
    bool config_change_pending;
    spinlock_t config_lock;
    spinlock_t vqs_list_lock; /* Protects VQs list access */
    struct device dev;
    struct virtio_device_id id;
    const struct virtio_config_ops *config;
    const struct vringh_config_ops *vringh_config;
    struct list_head vqs;
    u64 features;
    void *priv;
};

/**
 * virtio_driver - operations for a virtio I/O driver
 * @driver: underlying device driver (populate name and owner).
 * @id_table: the ids serviced by this driver.
 * @feature_table: an array of feature numbers supported by this driver.
 * @feature_table_size: number of entries in the feature table array.
 * @feature_table_legacy: same as feature_table but when working in legacy mode.
 * @feature_table_size_legacy: number of entries in feature table legacy array.
 * @probe: the function to call when a device is found.  Returns 0 or -errno.
 * @scan: optional function to call after successful probe; intended
 *    for virtio-scsi to invoke a scan.
 * @remove: the function to call when a device is removed.
 * @config_changed: optional function to call when the device configuration
 *    changes; may be called in interrupt context.
 * @freeze: optional function to call during suspend/hibernation.
 * @restore: optional function to call on resume.
 */
struct virtio_driver {
    struct device_driver driver;
    const struct virtio_device_id *id_table;
    const unsigned int *feature_table;
    unsigned int feature_table_size;
    const unsigned int *feature_table_legacy;
    unsigned int feature_table_size_legacy;
    int (*validate)(struct virtio_device *dev);
    int (*probe)(struct virtio_device *dev);
    void (*scan)(struct virtio_device *dev);
    void (*remove)(struct virtio_device *dev);
    void (*config_changed)(struct virtio_device *dev);
    int (*freeze)(struct virtio_device *dev);
    int (*restore)(struct virtio_device *dev);
};

int register_virtio_device(struct virtio_device *dev);

static inline struct virtio_device *dev_to_virtio(struct device *_dev)
{
    return container_of(_dev, struct virtio_device, dev);
}

static inline struct virtio_driver *drv_to_virtio(struct device_driver *drv)
{
    return container_of(drv, struct virtio_driver, driver);
}

void virtio_add_status(struct virtio_device *dev, unsigned int status);

int register_virtio_driver(struct virtio_driver *drv);
void unregister_virtio_driver(struct virtio_driver *drv);

#endif /* _LINUX_VIRTIO_H */

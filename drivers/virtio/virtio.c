// SPDX-License-Identifier: GPL-2.0-only
#include <linux/virtio.h>
#include <linux/spinlock.h>
#include <linux/virtio_config.h>
#include <linux/module.h>
#include <linux/idr.h>
#include <linux/of.h>
#include <uapi/linux/virtio_ids.h>

/* Unique numbering for virtio devices. */
static DEFINE_IDA(virtio_index_ida);

static inline int virtio_id_match(const struct virtio_device *dev,
                                  const struct virtio_device_id *id)
{
    if (id->device != dev->id.device && id->device != VIRTIO_DEV_ANY_ID)
        return 0;

    return id->vendor == VIRTIO_DEV_ANY_ID || id->vendor == dev->id.vendor;
}

/* This looks through all the IDs a driver claims to support.  If any of them
 * match, we return 1 and the kernel will call virtio_dev_probe(). */
static int virtio_dev_match(struct device *_dv, struct device_driver *_dr)
{
    unsigned int i;
    struct virtio_device *dev = dev_to_virtio(_dv);
    const struct virtio_device_id *ids;

    ids = drv_to_virtio(_dr)->id_table;
    for (i = 0; ids[i].device; i++)
        if (virtio_id_match(dev, &ids[i]))
            return 1;
    return 0;
}

static int virtio_dev_probe(struct device *_d)
{
    panic("%s: END!\n", __func__);
}

static void virtio_dev_remove(struct device *_d)
{
    struct virtio_device *dev = dev_to_virtio(_d);
    struct virtio_driver *drv = drv_to_virtio(dev->dev.driver);

    panic("%s: END!\n", __func__);
#if 0
    virtio_config_disable(dev);

    drv->remove(dev);

    /* Driver should have reset device. */
    WARN_ON_ONCE(dev->config->get_status(dev));

    /* Acknowledge the device's existence again. */
    virtio_add_status(dev, VIRTIO_CONFIG_S_ACKNOWLEDGE);

    of_node_put(dev->dev.of_node);
#endif
}

static struct bus_type virtio_bus = {
    .name       = "virtio",
    .match      = virtio_dev_match,
    //.dev_groups = virtio_dev_groups,
    //.uevent     = virtio_uevent,
    .probe      = virtio_dev_probe,
    .remove     = virtio_dev_remove,
};

static int virtio_device_of_init(struct virtio_device *dev)
{
    struct device_node *np, *pnode = dev_of_node(dev->dev.parent);
    char compat[] = "virtio,deviceXXXXXXXX";
    int ret, count;

    if (!pnode)
        return 0;

    count = of_get_available_child_count(pnode);
    if (!count)
        return 0;

    panic("%s: count(%d) END!\n", __func__, count);
}

/**
 * register_virtio_device - register virtio device
 * @dev        : virtio device to be registered
 *
 * On error, the caller must call put_device on &@dev->dev (and not kfree),
 * as another code path may have obtained a reference to @dev.
 *
 * Returns: 0 on suceess, -error on failure
 */
int register_virtio_device(struct virtio_device *dev)
{
    int err;

    dev->dev.bus = &virtio_bus;
    device_initialize(&dev->dev);

    /* Assign a unique device index and hence name. */
    err = ida_simple_get(&virtio_index_ida, 0, 0, GFP_KERNEL);
    if (err < 0)
        goto out;

    dev->index = err;
    dev_set_name(&dev->dev, "virtio%u", dev->index);

    err = virtio_device_of_init(dev);
    if (err)
        goto out_ida_remove;

    spin_lock_init(&dev->config_lock);
    dev->config_enabled = false;
    dev->config_change_pending = false;

    /* We always start by resetting the device, in case a previous
     * driver messed it up.  This also tests that code path a little. */
    dev->config->reset(dev);

    /* Acknowledge that we've seen the device. */
    virtio_add_status(dev, VIRTIO_CONFIG_S_ACKNOWLEDGE);

    INIT_LIST_HEAD(&dev->vqs);
    spin_lock_init(&dev->vqs_list_lock);

    /*
     * device_add() causes the bus infrastructure to look for a matching
     * driver.
     */
    err = device_add(&dev->dev);
    if (err)
        goto out_of_node_put;

    return 0;

 out_of_node_put:
    of_node_put(dev->dev.of_node);
 out_ida_remove:
    ida_simple_remove(&virtio_index_ida, dev->index);
 out:
    virtio_add_status(dev, VIRTIO_CONFIG_S_FAILED);
    return err;
}
EXPORT_SYMBOL_GPL(register_virtio_device);

void virtio_add_status(struct virtio_device *dev, unsigned int status)
{
    might_sleep();
    dev->config->set_status(dev, dev->config->get_status(dev) | status);
}
EXPORT_SYMBOL_GPL(virtio_add_status);

static int virtio_init(void)
{
    if (bus_register(&virtio_bus) != 0)
        panic("virtio bus registration failed");
    return 0;
}

static void __exit virtio_exit(void)
{
    bus_unregister(&virtio_bus);
    ida_destroy(&virtio_index_ida);
}

core_initcall(virtio_init);
module_exit(virtio_exit);

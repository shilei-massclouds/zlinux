// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Virtio memory mapped device driver
 *
 * Copyright 2011-2014, ARM Ltd.
 *
 * This module allows virtio devices to be used over a virtual, memory mapped
 * platform device.
 *
 * The guest device(s) may be instantiated in one of three equivalent ways:
 *
 * 1. Static platform device in board's code, eg.:
 *
 *  static struct platform_device v2m_virtio_device = {
 *      .name = "virtio-mmio",
 *      .id = -1,
 *      .num_resources = 2,
 *      .resource = (struct resource []) {
 *          {
 *              .start = 0x1001e000,
 *              .end = 0x1001e0ff,
 *              .flags = IORESOURCE_MEM,
 *          }, {
 *              .start = 42 + 32,
 *              .end = 42 + 32,
 *              .flags = IORESOURCE_IRQ,
 *          },
 *      }
 *  };
 *
 * 2. Device Tree node, eg.:
 *
 *      virtio_block@1e000 {
 *          compatible = "virtio,mmio";
 *          reg = <0x1e000 0x100>;
 *          interrupts = <42>;
 *      }
 *
 * 3. Kernel module (or command line) parameter. Can be used more than once -
 *    one device will be created for each one. Syntax:
 *
 *      [virtio_mmio.]device=<size>@<baseaddr>:<irq>[:<id>]
 *    where:
 *      <size>     := size (can use standard suffixes like K, M or G)
 *      <baseaddr> := physical base address
 *      <irq>      := interrupt number (as passed to request_irq())
 *      <id>       := (optional) platform device id
 *    eg.:
 *      virtio_mmio.device=0x100@0x100b0000:48 \
 *              virtio_mmio.device=1K@0x1001e000:74
 *
 * Based on Virtio PCI driver by Anthony Liguori, copyright IBM Corp. 2007
 */

#define pr_fmt(fmt) "virtio-mmio: " fmt

#include <linux/dma-mapping.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_mmio.h>
#if 0
#include <linux/virtio_ring.h>
#endif
#include <linux/mod_devicetable.h>

#define to_virtio_mmio_device(_plat_dev) \
    container_of(_plat_dev, struct virtio_mmio_device, vdev)

struct virtio_mmio_device {
    struct virtio_device vdev;
    struct platform_device *pdev;

    void __iomem *base;
    unsigned long version;

    /* a list of queues so we can dispatch IRQs */
    spinlock_t lock;
    struct list_head virtqueues;
};

static void virtio_mmio_release_dev(struct device *_d)
{
    struct virtio_device *vdev = container_of(_d, struct virtio_device, dev);
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
    struct platform_device *pdev = vm_dev->pdev;

    devm_kfree(&pdev->dev, vm_dev);
}

static void vm_get(struct virtio_device *vdev, unsigned offset,
                   void *buf, unsigned len)
{
    panic("%s: END!\n", __func__);
}

static void vm_set(struct virtio_device *vdev, unsigned offset,
                   const void *buf, unsigned len)
{
    panic("%s: END!\n", __func__);
}

static u32 vm_generation(struct virtio_device *vdev)
{
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

    if (vm_dev->version == 1)
        return 0;
    else
        return readl(vm_dev->base + VIRTIO_MMIO_CONFIG_GENERATION);
}

static u8 vm_get_status(struct virtio_device *vdev)
{
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

    return readl(vm_dev->base + VIRTIO_MMIO_STATUS) & 0xff;
}

static void vm_set_status(struct virtio_device *vdev, u8 status)
{
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

    /* We should never be setting status to 0. */
    BUG_ON(status == 0);

    writel(status, vm_dev->base + VIRTIO_MMIO_STATUS);
}

static void vm_reset(struct virtio_device *vdev)
{
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

    /* 0 status means a reset. */
    writel(0, vm_dev->base + VIRTIO_MMIO_STATUS);
}

static int vm_find_vqs(struct virtio_device *vdev, unsigned nvqs,
                       struct virtqueue *vqs[],
                       vq_callback_t *callbacks[],
                       const char * const names[],
                       const bool *ctx,
                       struct irq_affinity *desc)
{
    panic("%s: END!\n", __func__);
}

static void vm_del_vqs(struct virtio_device *vdev)
{
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
    struct virtqueue *vq, *n;

    panic("%s: END!\n", __func__);
#if 0
    list_for_each_entry_safe(vq, n, &vdev->vqs, list)
        vm_del_vq(vq);

    free_irq(platform_get_irq(vm_dev->pdev, 0), vm_dev);
#endif
}

/* Configuration interface */

static u64 vm_get_features(struct virtio_device *vdev)
{
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
    u64 features;

    writel(1, vm_dev->base + VIRTIO_MMIO_DEVICE_FEATURES_SEL);
    features = readl(vm_dev->base + VIRTIO_MMIO_DEVICE_FEATURES);
    features <<= 32;

    writel(0, vm_dev->base + VIRTIO_MMIO_DEVICE_FEATURES_SEL);
    features |= readl(vm_dev->base + VIRTIO_MMIO_DEVICE_FEATURES);

    return features;
}

static int vm_finalize_features(struct virtio_device *vdev)
{
    panic("%s: END!\n", __func__);
}

static const char *vm_bus_name(struct virtio_device *vdev)
{
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

    return vm_dev->pdev->name;
}

static bool vm_get_shm_region(struct virtio_device *vdev,
                              struct virtio_shm_region *region, u8 id)
{
    panic("%s: END!\n", __func__);
}

static const struct virtio_config_ops virtio_mmio_config_ops = {
    .get        = vm_get,
    .set        = vm_set,
    .generation = vm_generation,
    .get_status = vm_get_status,
    .set_status = vm_set_status,
    .reset      = vm_reset,
    .find_vqs   = vm_find_vqs,
    .del_vqs    = vm_del_vqs,
    .get_features   = vm_get_features,
    .finalize_features = vm_finalize_features,
    .bus_name       = vm_bus_name,
    .get_shm_region = vm_get_shm_region,
};

/* Platform device */

static int virtio_mmio_probe(struct platform_device *pdev)
{
    struct virtio_mmio_device *vm_dev;
    unsigned long magic;
    int rc;

    vm_dev = devm_kzalloc(&pdev->dev, sizeof(*vm_dev), GFP_KERNEL);
    if (!vm_dev)
        return -ENOMEM;

    vm_dev->vdev.dev.parent = &pdev->dev;
    vm_dev->vdev.dev.release = virtio_mmio_release_dev;
    vm_dev->vdev.config = &virtio_mmio_config_ops;
    vm_dev->pdev = pdev;
    INIT_LIST_HEAD(&vm_dev->virtqueues);
    spin_lock_init(&vm_dev->lock);

    vm_dev->base = devm_platform_ioremap_resource(pdev, 0);
    if (IS_ERR(vm_dev->base))
        return PTR_ERR(vm_dev->base);

    panic("%s: END!\n", __func__);
}

static int virtio_mmio_remove(struct platform_device *pdev)
{
    struct virtio_mmio_device *vm_dev = platform_get_drvdata(pdev);
    panic("%s: END!\n", __func__);
#if 0
    unregister_virtio_device(&vm_dev->vdev);

    return 0;
#endif
}

/* Platform driver */

static const struct of_device_id virtio_mmio_match[] = {
    { .compatible = "virtio,mmio", },
    {},
};
MODULE_DEVICE_TABLE(of, virtio_mmio_match);

static struct platform_driver virtio_mmio_driver = {
    .probe      = virtio_mmio_probe,
    .remove     = virtio_mmio_remove,
    .driver     = {
        .name   = "virtio-mmio",
        .of_match_table = virtio_mmio_match,
    },
};

static int __init virtio_mmio_init(void)
{
    return platform_driver_register(&virtio_mmio_driver);
}

static void __exit virtio_mmio_exit(void)
{
    platform_driver_unregister(&virtio_mmio_driver);
}

module_init(virtio_mmio_init);
module_exit(virtio_mmio_exit);

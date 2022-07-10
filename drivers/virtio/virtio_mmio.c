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
#include <linux/virtio_ring.h>
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_mmio.h>
#include <linux/mod_devicetable.h>

/* The alignment to use between consumer and producer parts of vring.
 * Currently hardcoded to the page size. */
#define VIRTIO_MMIO_VRING_ALIGN PAGE_SIZE

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

struct virtio_mmio_vq_info {
    /* the actual virtqueue */
    struct virtqueue *vq;

    /* the list node for the virtqueues list */
    struct list_head node;
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
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
    void __iomem *base = vm_dev->base + VIRTIO_MMIO_CONFIG;
    u8 b;
    __le16 w;
    __le32 l;

    if (vm_dev->version == 1) {
        u8 *ptr = buf;
        int i;

        for (i = 0; i < len; i++)
            ptr[i] = readb(base + offset + i);
        return;
    }

    switch (len) {
    case 1:
        b = readb(base + offset);
        memcpy(buf, &b, sizeof b);
        break;
    case 2:
        w = cpu_to_le16(readw(base + offset));
        memcpy(buf, &w, sizeof w);
        break;
    case 4:
        l = cpu_to_le32(readl(base + offset));
        memcpy(buf, &l, sizeof l);
        break;
    case 8:
        l = cpu_to_le32(readl(base + offset));
        memcpy(buf, &l, sizeof l);
        l = cpu_to_le32(ioread32(base + offset + sizeof l));
        memcpy(buf + sizeof l, &l, sizeof l);
        break;
    default:
        BUG();
    }
}

static void vm_set(struct virtio_device *vdev, unsigned offset,
                   const void *buf, unsigned len)
{
    panic("%s: END!\n", __func__);
}

/* Transport interface */

/* the notify function used when creating a virt queue */
static bool vm_notify(struct virtqueue *vq)
{
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vq->vdev);

    /* We write the queue's selector into the notification register to
     * signal the other end */
    writel(vq->index, vm_dev->base + VIRTIO_MMIO_QUEUE_NOTIFY);
    return true;
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

/* Notify all virtqueues on an interrupt. */
static irqreturn_t vm_interrupt(int irq, void *opaque)
{
    panic("%s: irq(%d) END!\n", __func__, irq);
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

static struct virtqueue *
vring_create_virtqueue_packed(unsigned int index,
                              unsigned int num,
                              unsigned int vring_align,
                              struct virtio_device *vdev,
                              bool weak_barriers,
                              bool may_reduce_num,
                              bool context,
                              bool (*notify)(struct virtqueue *),
                              void (*callback)(struct virtqueue *),
                              const char *name)
{
    panic("%s: END!\n", __func__);
}

static struct virtqueue *
vring_create_virtqueue_split(unsigned int index,
                             unsigned int num,
                             unsigned int vring_align,
                             struct virtio_device *vdev,
                             bool weak_barriers,
                             bool may_reduce_num,
                             bool context,
                             bool (*notify)(struct virtqueue *),
                             void (*callback)(struct virtqueue *),
                             const char *name)
{
    panic("%s: END!\n", __func__);
}

struct virtqueue *vring_create_virtqueue(
    unsigned int index,
    unsigned int num,
    unsigned int vring_align,
    struct virtio_device *vdev,
    bool weak_barriers,
    bool may_reduce_num,
    bool context,
    bool (*notify)(struct virtqueue *),
    void (*callback)(struct virtqueue *),
    const char *name)
{

    if (virtio_has_feature(vdev, VIRTIO_F_RING_PACKED))
        return vring_create_virtqueue_packed(index, num, vring_align,
                                             vdev, weak_barriers,
                                             may_reduce_num, context,
                                             notify, callback, name);

    return vring_create_virtqueue_split(index, num, vring_align,
                                        vdev, weak_barriers,
                                        may_reduce_num, context,
                                        notify, callback, name);
}
EXPORT_SYMBOL_GPL(vring_create_virtqueue);

static struct virtqueue *
vm_setup_vq(struct virtio_device *vdev, unsigned index,
            void (*callback)(struct virtqueue *vq),
            const char *name, bool ctx)
{
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
    struct virtio_mmio_vq_info *info;
    struct virtqueue *vq;
    unsigned long flags;
    unsigned int num;
    int err;

    if (!name)
        return NULL;

    /* Select the queue we're interested in */
    writel(index, vm_dev->base + VIRTIO_MMIO_QUEUE_SEL);

    /* Queue shouldn't already be set up. */
    if (readl(vm_dev->base + (vm_dev->version == 1 ?
                              VIRTIO_MMIO_QUEUE_PFN :
                              VIRTIO_MMIO_QUEUE_READY))) {
        err = -ENOENT;
        goto error_available;
    }

    /* Allocate and fill out our active queue description */
    info = kmalloc(sizeof(*info), GFP_KERNEL);
    if (!info) {
        err = -ENOMEM;
        goto error_kmalloc;
    }

    num = readl(vm_dev->base + VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (num == 0) {
        err = -ENOENT;
        goto error_new_virtqueue;
    }

    /* Create the vring */
    vq = vring_create_virtqueue(index, num, VIRTIO_MMIO_VRING_ALIGN,
                                vdev, true, true, ctx, vm_notify,
                                callback, name);
    if (!vq) {
        err = -ENOMEM;
        goto error_new_virtqueue;
    }

    panic("%s: name(%s) num(%d) END!\n", __func__, name, num);
    return vq;

 error_bad_pfn:
    vring_del_virtqueue(vq);

 error_new_virtqueue:
    if (vm_dev->version == 1) {
        writel(0, vm_dev->base + VIRTIO_MMIO_QUEUE_PFN);
    } else {
        writel(0, vm_dev->base + VIRTIO_MMIO_QUEUE_READY);
        WARN_ON(readl(vm_dev->base + VIRTIO_MMIO_QUEUE_READY));
    }
    kfree(info);
error_kmalloc:
error_available:
    return ERR_PTR(err);

}

static int vm_find_vqs(struct virtio_device *vdev, unsigned nvqs,
                       struct virtqueue *vqs[],
                       vq_callback_t *callbacks[],
                       const char * const names[],
                       const bool *ctx,
                       struct irq_affinity *desc)
{
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);
    int irq = platform_get_irq(vm_dev->pdev, 0);
    int i, err, queue_idx = 0;

    if (irq < 0)
        return irq;

    err = request_irq(irq, vm_interrupt, IRQF_SHARED,
                      dev_name(&vdev->dev), vm_dev);
    if (err)
        return err;

    for (i = 0; i < nvqs; ++i) {
        if (!names[i]) {
            vqs[i] = NULL;
            continue;
        }

        vqs[i] = vm_setup_vq(vdev, queue_idx++, callbacks[i], names[i],
                             ctx ? ctx[i] : false);
        if (IS_ERR(vqs[i])) {
            vm_del_vqs(vdev);
            return PTR_ERR(vqs[i]);
        }
    }

    panic("%s: irq(%d) END!\n", __func__, irq);
    return 0;
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
    struct virtio_mmio_device *vm_dev = to_virtio_mmio_device(vdev);

    /* Give virtio_ring a chance to accept features. */
    vring_transport_features(vdev);

    /* Make sure there are no mixed devices */
    if (vm_dev->version == 2 && !__virtio_test_bit(vdev, VIRTIO_F_VERSION_1)) {
        pr_err("New virtio-mmio devices (version 2) must provide "
               "VIRTIO_F_VERSION_1 feature!\n");
        return -EINVAL;
    }

    writel(1, vm_dev->base + VIRTIO_MMIO_DRIVER_FEATURES_SEL);
    writel((u32)(vdev->features >> 32),
           vm_dev->base + VIRTIO_MMIO_DRIVER_FEATURES);

    writel(0, vm_dev->base + VIRTIO_MMIO_DRIVER_FEATURES_SEL);
    writel((u32)vdev->features,
           vm_dev->base + VIRTIO_MMIO_DRIVER_FEATURES);

    return 0;
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

    /* Check magic value */
    magic = readl(vm_dev->base + VIRTIO_MMIO_MAGIC_VALUE);
    if (magic != ('v' | 'i' << 8 | 'r' << 16 | 't' << 24)) {
        pr_warn("Wrong magic value 0x%08lx!\n", magic);
        return -ENODEV;
    }

    /* Check device version */
    vm_dev->version = readl(vm_dev->base + VIRTIO_MMIO_VERSION);
    if (vm_dev->version < 1 || vm_dev->version > 2) {
        pr_err("Version %ld not supported!\n", vm_dev->version);
        return -ENXIO;
    }

    vm_dev->vdev.id.device = readl(vm_dev->base + VIRTIO_MMIO_DEVICE_ID);
    if (vm_dev->vdev.id.device == 0) {
        /*
         * virtio-mmio device with an ID 0 is a (dummy) placeholder
         * with no function. End probing now with no error reported.
         */
        return -ENODEV;
    }
    vm_dev->vdev.id.vendor = readl(vm_dev->base + VIRTIO_MMIO_VENDOR_ID);

    if (vm_dev->version == 1) {
        writel(PAGE_SIZE, vm_dev->base + VIRTIO_MMIO_GUEST_PAGE_SIZE);

        rc = dma_set_mask(&pdev->dev, DMA_BIT_MASK(64));
        /*
         * In the legacy case, ensure our coherently-allocated virtio
         * ring will be at an address expressable as a 32-bit PFN.
         */
        if (!rc)
            dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(32 + PAGE_SHIFT));
    } else {
        rc = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
    }
    if (rc)
        rc = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
    if (rc)
        pr_warn("Failed to enable 64-bit or 32-bit DMA."
                "  Trying to continue, but this might not work.\n");

    platform_set_drvdata(pdev, vm_dev);

    rc = register_virtio_device(&vm_dev->vdev);
    if (rc)
        put_device(&vm_dev->vdev.dev);

    return rc;
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

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

#if 0
#include <linux/acpi.h>
#include <linux/dma-mapping.h>
#endif
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#if 0
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <uapi/linux/virtio_mmio.h>
#include <linux/virtio_ring.h>
#endif
#include <linux/mod_devicetable.h>

/* Platform device */

static int virtio_mmio_probe(struct platform_device *pdev)
{
    struct virtio_mmio_device *vm_dev;
    unsigned long magic;
    int rc;

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

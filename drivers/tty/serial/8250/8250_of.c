// SPDX-License-Identifier: GPL-2.0+
/*
 *  Serial Port driver for Open Firmware platform devices
 *
 *    Copyright (C) 2006 Arnd Bergmann <arnd@arndb.de>, IBM Corp.
 */
#include <linux/console.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/serial_core.h>
//#include <linux/serial_reg.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <uapi/linux/serial.h>
#include <uapi/linux/serial_core.h>
#if 0
#include <linux/pm_runtime.h>
#include <linux/clk.h>
#include <linux/reset.h>
#endif

#include "8250.h"

struct of_serial_info {
#if 0
    struct clk *clk;
    struct reset_control *rst;
#endif
    int type;
    int line;
};

/*
 * Fill a struct uart_port for a given device node
 */
static int of_platform_serial_setup(struct platform_device *ofdev,
                                    int type, struct uart_8250_port *up,
                                    struct of_serial_info *info)
{
    struct resource resource;
    struct device_node *np = ofdev->dev.of_node;
    struct uart_port *port = &up->port;
    u32 clk, spd, prop;
    int ret, irq;

    memset(port, 0, sizeof *port);

#if 0
    pm_runtime_enable(&ofdev->dev);
    pm_runtime_get_sync(&ofdev->dev);
#endif

    if (of_property_read_u32(np, "clock-frequency", &clk)) {
        panic("%s: clock-frequency!\n", __func__);
    }
    /* If current-speed was set, then try not to change it. */
    if (of_property_read_u32(np, "current-speed", &spd) == 0)
        port->custom_divisor = clk / (16 * spd);

    ret = of_address_to_resource(np, 0, &resource);
    if (ret) {
        dev_warn(&ofdev->dev, "invalid address\n");
        goto err_unprepare;
    }

    port->flags = UPF_SHARE_IRQ | UPF_BOOT_AUTOCONF | UPF_FIXED_PORT |
                  UPF_FIXED_TYPE;
    spin_lock_init(&port->lock);

    if (resource_type(&resource) == IORESOURCE_IO) {
        port->iotype = UPIO_PORT;
        port->iobase = resource.start;
    } else {
        port->mapbase = resource.start;
        port->mapsize = resource_size(&resource);

        /* Check for shifted address mapping */
        if (of_property_read_u32(np, "reg-offset", &prop) == 0) {
            panic("%s: reg-offset!\n", __func__);
        }

        port->iotype = UPIO_MEM;
        if (of_property_read_u32(np, "reg-io-width", &prop) == 0) {
            switch (prop) {
            case 1:
                port->iotype = UPIO_MEM;
                break;
            case 2:
                port->iotype = UPIO_MEM16;
                break;
            case 4:
                port->iotype = of_device_is_big_endian(np) ?
                           UPIO_MEM32BE : UPIO_MEM32;
                break;
            default:
                dev_warn(&ofdev->dev, "unsupported reg-io-width (%d)\n",
                         prop);
                ret = -EINVAL;
                goto err_unprepare;
            }
        }
        port->flags |= UPF_IOREMAP;
    }

    /* Compatibility with the deprecated pxa driver and 8250_pxa drivers. */
    if (of_device_is_compatible(np, "mrvl,mmp-uart"))
        port->regshift = 2;

    /* Check for registers offset within the devices address range */
    if (of_property_read_u32(np, "reg-shift", &prop) == 0)
        port->regshift = prop;

    /* Check for fifo size */
    if (of_property_read_u32(np, "fifo-size", &prop) == 0)
        port->fifosize = prop;

    /* Check for a fixed line number */
    ret = of_alias_get_id(np, "serial");
    if (ret >= 0)
        port->line = ret;

    irq = of_irq_get(np, 0);
    if (irq < 0) {
        if (irq == -EPROBE_DEFER) {
            ret = -EPROBE_DEFER;
            goto err_unprepare;
        }
        /* IRQ support not mandatory */
        irq = 0;
    }

    port->irq = irq;

#if 0
    info->rst = devm_reset_control_get_optional_shared(&ofdev->dev, NULL);
    if (IS_ERR(info->rst)) {
        ret = PTR_ERR(info->rst);
        goto err_unprepare;
    }

    ret = reset_control_deassert(info->rst);
    if (ret)
        goto err_unprepare;
#endif

    port->type = type;
    port->uartclk = clk;

    if (of_property_read_bool(np, "no-loopback-test"))
        port->flags |= UPF_SKIP_TEST;

    port->dev = &ofdev->dev;
    port->rs485_config = serial8250_em485_config;
    up->rs485_start_tx = serial8250_em485_start_tx;
    up->rs485_stop_tx = serial8250_em485_stop_tx;

    switch (type) {
    case PORT_RT2880:
        port->iotype = UPIO_AU;
        break;
    }

    return 0;
 err_unprepare:
    //clk_disable_unprepare(info->clk);
 err_pmruntime:
#if 0
    pm_runtime_put_sync(&ofdev->dev);
    pm_runtime_disable(&ofdev->dev);
#endif
    return ret;
}

/*
 * Try to register a serial port
 */
static int of_platform_serial_probe(struct platform_device *ofdev)
{
    struct of_serial_info *info;
    struct uart_8250_port port8250;
    unsigned int port_type;
    u32 tx_threshold;
    int ret;

    port_type = (unsigned long) of_device_get_match_data(&ofdev->dev);
    if (port_type == PORT_UNKNOWN)
        return -EINVAL;

    if (of_property_read_bool(ofdev->dev.of_node, "used-by-rtas"))
        return -EBUSY;

    info = kzalloc(sizeof(*info), GFP_KERNEL);
    if (info == NULL)
        return -ENOMEM;

    memset(&port8250, 0, sizeof(port8250));
    ret = of_platform_serial_setup(ofdev, port_type, &port8250, info);
    if (ret)
        goto err_free;

    if (port8250.port.fifosize)
        port8250.capabilities = UART_CAP_FIFO;

    /* Check for TX FIFO threshold & set tx_loadsz */
    if ((of_property_read_u32(ofdev->dev.of_node, "tx-threshold",
                              &tx_threshold) == 0) &&
        (tx_threshold < port8250.port.fifosize))
        port8250.tx_loadsz = port8250.port.fifosize - tx_threshold;

    if (of_property_read_bool(ofdev->dev.of_node, "auto-flow-control"))
        port8250.capabilities |= UART_CAP_AFE;

    if (of_property_read_u32(ofdev->dev.of_node,
                             "overrun-throttle-ms",
                             &port8250.overrun_backoff_time_ms) != 0)
        port8250.overrun_backoff_time_ms = 0;

    ret = serial8250_register_8250_port(&port8250);
    if (ret < 0)
        goto err_dispose;

    info->type = port_type;
    info->line = ret;
    platform_set_drvdata(ofdev, info);
    return 0;

 err_dispose:
#if 0
    irq_dispose_mapping(port8250.port.irq);
    pm_runtime_put_sync(&ofdev->dev);
    pm_runtime_disable(&ofdev->dev);
    clk_disable_unprepare(info->clk);
#endif
 err_free:
    kfree(info);
    return ret;
}

/*
 * Release a line
 */
static int of_platform_serial_remove(struct platform_device *ofdev)
{
#if 0
    struct of_serial_info *info = platform_get_drvdata(ofdev);

    serial8250_unregister_port(info->line);

    reset_control_assert(info->rst);
    pm_runtime_put_sync(&ofdev->dev);
    pm_runtime_disable(&ofdev->dev);
    clk_disable_unprepare(info->clk);
    kfree(info);
#endif
    panic("%s: END!\n", __func__);
    return 0;
}

/*
 * A few common types, add more as needed.
 */
static const struct of_device_id of_platform_serial_table[] = {
    { .compatible = "ns8250",   .data = (void *)PORT_8250, },
    { .compatible = "ns16450",  .data = (void *)PORT_16450, },
    { .compatible = "ns16550a", .data = (void *)PORT_16550A, },
    { .compatible = "ns16550",  .data = (void *)PORT_16550, },
    { .compatible = "ns16750",  .data = (void *)PORT_16750, },
    { .compatible = "ns16850",  .data = (void *)PORT_16850, },
    { /* end of list */ },
};
MODULE_DEVICE_TABLE(of, of_platform_serial_table);

#if 0
static SIMPLE_DEV_PM_OPS(of_serial_pm_ops,
                         of_serial_suspend,
                         of_serial_resume);
#endif

static struct platform_driver of_platform_serial_driver = {
    .driver = {
        .name = "of_serial",
        .of_match_table = of_platform_serial_table,
        //.pm = &of_serial_pm_ops,
    },
    .probe = of_platform_serial_probe,
    .remove = of_platform_serial_remove,
};

module_platform_driver(of_platform_serial_driver);

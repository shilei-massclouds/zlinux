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
#include <uapi/linux/serial.h>
#if 0
#include <linux/pm_runtime.h>
#include <linux/clk.h>
#include <linux/reset.h>

#include "8250.h"
#endif

/*
 * Try to register a serial port
 */
static int of_platform_serial_probe(struct platform_device *ofdev)
{
    panic("%s: END!\n", __func__);
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

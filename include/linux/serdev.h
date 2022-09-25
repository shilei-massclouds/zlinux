/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2016-2017 Linaro Ltd., Rob Herring <robh@kernel.org>
 */
#ifndef _LINUX_SERDEV_H
#define _LINUX_SERDEV_H

#include <linux/types.h>
#include <linux/device.h>
#include <linux/termios.h>
#include <linux/delay.h>

struct serdev_controller;
struct serdev_device;

static inline
struct device *serdev_tty_port_register(struct tty_port *port,
                                        struct device *parent,
                                        struct tty_driver *drv, int idx)
{
    return ERR_PTR(-ENODEV);
}

static inline int serdev_tty_port_unregister(struct tty_port *port)
{
    return -ENODEV;
}

#endif /*_LINUX_SERDEV_H */

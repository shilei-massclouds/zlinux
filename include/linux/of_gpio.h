/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * OF helpers for the GPIO API
 *
 * Copyright (c) 2007-2008  MontaVista Software, Inc.
 *
 * Author: Anton Vorontsov <avorontsov@ru.mvista.com>
 */

#ifndef __LINUX_OF_GPIO_H
#define __LINUX_OF_GPIO_H

#include <linux/compiler.h>
//#include <linux/gpio/driver.h>
//#include <linux/gpio.h>     /* FIXME: Shouldn't be here */
#include <linux/of.h>

struct device_node;

/*
 * This is Linux-specific flags. By default controllers' and Linux' mapping
 * match, but GPIO controllers are free to translate their own flags to
 * Linux-specific in their .xlate callback. Though, 1:1 mapping is recommended.
 */
enum of_gpio_flags {
    OF_GPIO_ACTIVE_LOW = 0x1,
    OF_GPIO_SINGLE_ENDED = 0x2,
    OF_GPIO_OPEN_DRAIN = 0x4,
    OF_GPIO_TRANSITORY = 0x8,
    OF_GPIO_PULL_UP = 0x10,
    OF_GPIO_PULL_DOWN = 0x20,
};

#endif /* __LINUX_OF_GPIO_H */

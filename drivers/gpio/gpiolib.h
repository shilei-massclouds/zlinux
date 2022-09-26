/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Internal GPIO functions.
 *
 * Copyright (C) 2013, Intel Corporation
 * Author: Mika Westerberg <mika.westerberg@linux.intel.com>
 */

#ifndef GPIOLIB_H
#define GPIOLIB_H

//#include <linux/gpio/driver.h>
#include <linux/gpio/consumer.h> /* for enum gpiod_flags */
#include <linux/err.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/cdev.h>

/* gpio suffixes used for ACPI and device tree lookup */
static __maybe_unused const char * const gpio_suffixes[] =
{ "gpios", "gpio" };

#define gpiod_not_found(desc) \
    (IS_ERR(desc) && PTR_ERR(desc) == -ENOENT)

#endif /* GPIOLIB_H */

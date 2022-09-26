// SPDX-License-Identifier: GPL-2.0+
/*
 * OF helpers for the GPIO API
 *
 * Copyright (c) 2007-2008  MontaVista Software, Inc.
 *
 * Author: Anton Vorontsov <avorontsov@ru.mvista.com>
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/gpio/consumer.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_gpio.h>
#if 0
#include <linux/pinctrl/pinctrl.h>
#include <linux/gpio/machine.h>
#endif
#include <linux/slab.h>

#include "gpiolib.h"
#include "gpiolib-of.h"

/**
 * of_get_named_gpiod_flags() - Get a GPIO descriptor and flags for GPIO API
 * @np:     device node to get GPIO from
 * @propname:   property name containing gpio specifier(s)
 * @index:  index of the GPIO
 * @flags:  a flags pointer to fill in
 *
 * Returns GPIO descriptor to use with Linux GPIO API, or one of the errno
 * value on the error condition. If @flags is not NULL the function also fills
 * in flags for the GPIO.
 */
static struct gpio_desc *
of_get_named_gpiod_flags(const struct device_node *np,
                         const char *propname, int index,
                         enum of_gpio_flags *flags)
{
    struct of_phandle_args gpiospec;
    struct gpio_chip *chip;
    struct gpio_desc *desc;
    int ret;

#if 0
    ret = of_parse_phandle_with_args_map(np, propname, "gpio", index,
                                         &gpiospec);
    if (ret) {
        pr_debug("%s: can't parse '%s' property of node '%pOF[%d]'\n",
                 __func__, propname, np, index);
        return ERR_PTR(ret);
    }
#endif

    panic("%s: END!\n", __func__);
}

struct gpio_desc *of_find_gpio(struct device *dev, const char *con_id,
                               unsigned int idx, unsigned long *flags)
{
    char prop_name[32]; /* 32 is max size of property name */
    enum of_gpio_flags of_flags;
    struct gpio_desc *desc;
    unsigned int i;

    /* Try GPIO property "foo-gpios" and "foo-gpio" */
    for (i = 0; i < ARRAY_SIZE(gpio_suffixes); i++) {
        if (con_id)
            snprintf(prop_name, sizeof(prop_name), "%s-%s", con_id,
                     gpio_suffixes[i]);
        else
            snprintf(prop_name, sizeof(prop_name), "%s",
                     gpio_suffixes[i]);

        desc = of_get_named_gpiod_flags(dev->of_node, prop_name, idx,
                                        &of_flags);

        if (!gpiod_not_found(desc))
            break;
    }

    panic("%s: END!\n", __func__);
}

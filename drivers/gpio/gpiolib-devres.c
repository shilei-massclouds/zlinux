/* SPDX-License-Identifier: GPL-2.0 */
/*
 * devres.c - managed gpio resources
 * This file is based on kernel/irq/devres.c
 *
 * Copyright (c) 2011 John Crispin <john@phrozen.org>
 */

#include <linux/module.h>
#include <linux/err.h>
//#include <linux/gpio.h>
#include <linux/gpio/consumer.h>
#include <linux/device.h>
#include <linux/gfp.h>

#include "gpiolib.h"

/**
 * devm_gpiod_get_index - Resource-managed gpiod_get_index()
 * @dev:    GPIO consumer
 * @con_id: function within the GPIO consumer
 * @idx:    index of the GPIO to obtain in the consumer
 * @flags:  optional GPIO initialization flags
 *
 * Managed gpiod_get_index(). GPIO descriptors returned from this function are
 * automatically disposed on driver detach. See gpiod_get_index() for detailed
 * information about behavior and return values.
 */
struct gpio_desc *__must_check devm_gpiod_get_index(struct device *dev,
                            const char *con_id,
                            unsigned int idx,
                            enum gpiod_flags flags)
{
    struct gpio_desc **dr;
    struct gpio_desc *desc;

    desc = gpiod_get_index(dev, con_id, idx, flags);
    if (IS_ERR(desc))
        return desc;

    panic("%s: END!\n", __func__);
}

/**
 * devm_gpiod_get_index_optional - Resource-managed gpiod_get_index_optional()
 * @dev: GPIO consumer
 * @con_id: function within the GPIO consumer
 * @index: index of the GPIO to obtain in the consumer
 * @flags: optional GPIO initialization flags
 *
 * Managed gpiod_get_index_optional(). GPIO descriptors returned from this
 * function are automatically disposed on driver detach. See
 * gpiod_get_index_optional() for detailed information about behavior and
 * return values.
 */
struct gpio_desc *__must_check devm_gpiod_get_index_optional(struct device *dev,
                                 const char *con_id,
                                 unsigned int index,
                                 enum gpiod_flags flags)
{
    struct gpio_desc *desc;

    desc = devm_gpiod_get_index(dev, con_id, index, flags);
    if (gpiod_not_found(desc))
        return NULL;

    return desc;
}
EXPORT_SYMBOL_GPL(devm_gpiod_get_index_optional);

/**
 * devm_gpiod_get_optional - Resource-managed gpiod_get_optional()
 * @dev: GPIO consumer
 * @con_id: function within the GPIO consumer
 * @flags: optional GPIO initialization flags
 *
 * Managed gpiod_get_optional(). GPIO descriptors returned from this function
 * are automatically disposed on driver detach. See gpiod_get_optional() for
 * detailed information about behavior and return values.
 */
struct gpio_desc *__must_check devm_gpiod_get_optional(struct device *dev,
                               const char *con_id,
                               enum gpiod_flags flags)
{
    return devm_gpiod_get_index_optional(dev, con_id, 0, flags);
}
EXPORT_SYMBOL_GPL(devm_gpiod_get_optional);

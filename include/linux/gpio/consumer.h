/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_GPIO_CONSUMER_H
#define __LINUX_GPIO_CONSUMER_H

#include <linux/bits.h>
#include <linux/bug.h>
#include <linux/compiler_types.h>
#include <linux/err.h>

struct device;
struct gpio_desc;
struct gpio_array;

#define GPIOD_FLAGS_BIT_DIR_SET     BIT(0)
#define GPIOD_FLAGS_BIT_DIR_OUT     BIT(1)
#define GPIOD_FLAGS_BIT_DIR_VAL     BIT(2)
#define GPIOD_FLAGS_BIT_OPEN_DRAIN  BIT(3)
#define GPIOD_FLAGS_BIT_NONEXCLUSIVE    BIT(4)

/**
 * enum gpiod_flags - Optional flags that can be passed to one of gpiod_* to
 *                    configure direction and output value. These values
 *                    cannot be OR'd.
 *
 * @GPIOD_ASIS:         Don't change anything
 * @GPIOD_IN:           Set lines to input mode
 * @GPIOD_OUT_LOW:      Set lines to output and drive them low
 * @GPIOD_OUT_HIGH:     Set lines to output and drive them high
 * @GPIOD_OUT_LOW_OPEN_DRAIN:   Set lines to open-drain output and drive them low
 * @GPIOD_OUT_HIGH_OPEN_DRAIN:  Set lines to open-drain output and drive them high
 */
enum gpiod_flags {
    GPIOD_ASIS  = 0,
    GPIOD_IN    = GPIOD_FLAGS_BIT_DIR_SET,
    GPIOD_OUT_LOW   = GPIOD_FLAGS_BIT_DIR_SET | GPIOD_FLAGS_BIT_DIR_OUT,
    GPIOD_OUT_HIGH  = GPIOD_FLAGS_BIT_DIR_SET | GPIOD_FLAGS_BIT_DIR_OUT |
              GPIOD_FLAGS_BIT_DIR_VAL,
    GPIOD_OUT_LOW_OPEN_DRAIN = GPIOD_OUT_LOW | GPIOD_FLAGS_BIT_OPEN_DRAIN,
    GPIOD_OUT_HIGH_OPEN_DRAIN = GPIOD_OUT_HIGH | GPIOD_FLAGS_BIT_OPEN_DRAIN,
};

struct gpio_desc *__must_check
devm_gpiod_get_optional(struct device *dev, const char *con_id,
                        enum gpiod_flags flags);

struct gpio_desc *__must_check gpiod_get_index(struct device *dev,
                                               const char *con_id,
                                               unsigned int idx,
                                               enum gpiod_flags flags);

#endif /* __LINUX_GPIO_CONSUMER_H */

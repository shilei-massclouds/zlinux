/* SPDX-License-Identifier: GPL-2.0 */

#ifndef GPIOLIB_OF_H
#define GPIOLIB_OF_H

struct gpio_chip;
enum of_gpio_flags;

struct gpio_desc *of_find_gpio(struct device *dev,
                   const char *con_id,
                   unsigned int idx,
                   unsigned long *lookupflags);
int of_gpiochip_add(struct gpio_chip *gc);
void of_gpiochip_remove(struct gpio_chip *gc);
int of_gpio_get_count(struct device *dev, const char *con_id);
bool of_gpio_need_valid_mask(const struct gpio_chip *gc);
void of_gpio_dev_init(struct gpio_chip *gc, struct gpio_device *gdev);

extern struct notifier_block gpio_of_notifier;

#endif /* GPIOLIB_OF_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_GPIO_MACHINE_H
#define __LINUX_GPIO_MACHINE_H

#include <linux/types.h>
#include <linux/list.h>

enum gpio_lookup_flags {
    GPIO_ACTIVE_HIGH        = (0 << 0),
    GPIO_ACTIVE_LOW         = (1 << 0),
    GPIO_OPEN_DRAIN         = (1 << 1),
    GPIO_OPEN_SOURCE        = (1 << 2),
    GPIO_PERSISTENT         = (0 << 3),
    GPIO_TRANSITORY         = (1 << 3),
    GPIO_PULL_UP            = (1 << 4),
    GPIO_PULL_DOWN          = (1 << 5),

    GPIO_LOOKUP_FLAGS_DEFAULT   = GPIO_ACTIVE_HIGH | GPIO_PERSISTENT,
};

#endif /* __LINUX_GPIO_MACHINE_H */

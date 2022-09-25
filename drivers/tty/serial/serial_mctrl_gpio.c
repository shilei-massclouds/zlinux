// SPDX-License-Identifier: GPL-2.0+
/*
 * Helpers for controlling modem lines via GPIO
 *
 * Copyright (C) 2014 Paratronic S.A.
 */

#include <linux/err.h>
#include <linux/device.h>
#include <linux/irq.h>
#include <linux/gpio/consumer.h>
#include <linux/termios.h>
#include <linux/serial_core.h>
#include <linux/module.h>
#include <linux/property.h>

#include "serial_mctrl_gpio.h"

struct mctrl_gpios {
    struct uart_port *port;
    struct gpio_desc *gpio[UART_GPIO_MAX];
    int irq[UART_GPIO_MAX];
    unsigned int mctrl_prev;
    bool mctrl_on;
};

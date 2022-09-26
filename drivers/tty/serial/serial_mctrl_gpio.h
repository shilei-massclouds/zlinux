/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Helpers for controlling modem lines via GPIO
 *
 * Copyright (C) 2014 Paratronic S.A.
 */

#ifndef __SERIAL_MCTRL_GPIO__
#define __SERIAL_MCTRL_GPIO__

#include <linux/err.h>
#include <linux/device.h>
//#include <linux/gpio/consumer.h>

struct uart_port;

enum mctrl_gpio_idx {
    UART_GPIO_CTS,
    UART_GPIO_DSR,
    UART_GPIO_DCD,
    UART_GPIO_RNG,
    UART_GPIO_RI = UART_GPIO_RNG,
    UART_GPIO_RTS,
    UART_GPIO_DTR,
    UART_GPIO_MAX,
};

/*
 * Opaque descriptor for modem lines controlled by GPIOs
 */
struct mctrl_gpios;

/*
 * Request and set direction of modem control line GPIOs and set up irq
 * handling.
 * devm_* functions are used, so there's no need to call mctrl_gpio_free().
 * Returns a pointer to the allocated mctrl structure if ok, -ENOMEM on
 * allocation error.
 */
struct mctrl_gpios *
mctrl_gpio_init(struct uart_port *port, unsigned int idx);

#endif /* __SERIAL_MCTRL_GPIO__ */

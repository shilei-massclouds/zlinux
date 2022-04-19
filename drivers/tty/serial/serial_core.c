// SPDX-License-Identifier: GPL-2.0+
/*
 *  Driver core for serial ports
 *
 *  Based on drivers/char/serial.c, by Linus Torvalds, Theodore Ts'o.
 *
 *  Copyright 1999 ARM Limited
 *  Copyright (C) 2000-2001 Deep Blue Solutions Ltd.
 */
#include <linux/module.h>
/*
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
*/
#include <linux/init.h>
#include <linux/console.h>
#if 0
#include <linux/gpio/consumer.h>
#include <linux/of.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/device.h>
#include <linux/serial.h> /* for serial_state and serial_icounter_struct */
#endif
#include <linux/serial_core.h>
/*
#include <linux/sysrq.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/security.h>

#include <linux/irq.h>
*/
#include <linux/uaccess.h>

/**
 *  uart_console_write - write a console message to a serial port
 *  @port: the port to write the message
 *  @s: array of characters
 *  @count: number of characters in string to write
 *  @putchar: function to write character to port
 */
void uart_console_write(struct uart_port *port,
                        const char *s, unsigned int count,
                        void (*putchar)(struct uart_port *, int))
{
    unsigned int i;

    for (i = 0; i < count; i++, s++) {
        if (*s == '\n')
            putchar(port, '\r');
        putchar(port, *s);
    }
}
EXPORT_SYMBOL_GPL(uart_console_write);

// SPDX-License-Identifier: GPL-2.0
/*
 * Early serial console for 8250/16550 devices
 *
 * (c) Copyright 2004 Hewlett-Packard Development Company, L.P.
 *  Bjorn Helgaas <bjorn.helgaas@hp.com>
 *
 * Based on the 8250.c serial driver, Copyright (C) 2001 Russell King,
 * and on early_printk.c by Andi Kleen.
 *
 * This is for use before the serial driver has initialized, in
 * particular, before the UARTs have been discovered and named.
 * Instead of specifying the console device as, e.g., "ttyS0",
 * we locate the device directly by its MMIO or I/O port address.
 *
 * The user can specify the device directly, e.g.,
 *  earlycon=uart8250,io,0x3f8,9600n8
 *  earlycon=uart8250,mmio,0xff5e0000,115200n8
 *  earlycon=uart8250,mmio32,0xff5e0000,115200n8
 * or
 *  console=uart8250,io,0x3f8,9600n8
 *  console=uart8250,mmio,0xff5e0000,115200n8
 *  console=uart8250,mmio32,0xff5e0000,115200n8
 */

#include <linux/tty.h>
#include <linux/init.h>
#include <linux/console.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/serial_reg.h>
#include <linux/serial.h>
#include <linux/serial_8250.h>
#include <asm/io.h>
//#include <asm/serial.h>

int __init early_serial8250_setup(struct earlycon_device *device,
                                  const char *options)
{
#if 0
    if (!(device->port.membase || device->port.iobase))
        return -ENODEV;

    if (!device->baud) {
        struct uart_port *port = &device->port;
        unsigned int ier;

        /* assume the device was initialized, only mask interrupts */
        ier = serial8250_early_in(port, UART_IER);
        serial8250_early_out(port, UART_IER, ier & UART_IER_UUE);
    } else
        init_port(device);

    device->con->write = early_serial8250_write;
    device->con->read = early_serial8250_read;
    return 0;
#endif
    panic("%s: END!\n", __func__);
}

EARLYCON_DECLARE(uart8250, early_serial8250_setup);
EARLYCON_DECLARE(uart, early_serial8250_setup);
OF_EARLYCON_DECLARE(ns16550a, "ns16550a", early_serial8250_setup);

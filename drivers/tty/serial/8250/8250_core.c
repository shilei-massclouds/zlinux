// SPDX-License-Identifier: GPL-2.0+
/*
 *  Universal/legacy driver for 8250/16550-type serial ports
 *
 *  Based on drivers/char/serial.c, by Linus Torvalds, Theodore Ts'o.
 *
 *  Copyright (C) 2001 Russell King.
 *
 *  Supports: ISA-compatible 8250/16550 ports
 *        PNP 8250/16550 ports
 *        early_serial_setup() ports
 *        userspace-configurable "phantom" ports
 *        "serial8250" platform devices
 *        serial8250_register_8250_port() ports
 */

//#include <linux/acpi.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/console.h>
//#include <linux/sysrq.h>
#include <linux/delay.h>
#include <linux/platform_device.h>
#include <linux/tty.h>
#include <linux/ratelimit.h>
//#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/serial_8250.h>
#include <linux/nmi.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
//#include <linux/pm_runtime.h>
#include <linux/io.h>

#include <asm/irq.h>

#include "8250.h"

#define UART_NR CONFIG_SERIAL_8250_NR_UARTS

static struct uart_driver serial8250_reg;

static const struct uart_ops *base_ops;
static struct uart_ops univ8250_port_ops;

static int univ8250_setup_irq(struct uart_8250_port *up)
{
    panic("%s: END!\n", __func__);
}

static void univ8250_release_irq(struct uart_8250_port *up)
{
    panic("%s: END!\n", __func__);
}

static const struct uart_8250_ops univ8250_driver_ops = {
    .setup_irq      = univ8250_setup_irq,
    .release_irq    = univ8250_release_irq,
};

static struct uart_8250_port serial8250_ports[UART_NR];

/*
 * Configuration:
 *   share_irqs - whether we pass IRQF_SHARED to request_irq().  This option
 *                is unsafe when used on edge-triggered interrupts.
 */
static unsigned int share_irqs = SERIAL8250_SHARE_IRQS;

static unsigned int nr_uarts = CONFIG_SERIAL_8250_RUNTIME_UARTS;

/* force skip of txen test at init time */
static unsigned int skip_txen_test;

/*
 * This "device" covers _all_ ISA 8250-compatible serial devices listed
 * in the table in include/asm/serial.h
 */
static struct platform_device *serial8250_isa_devs;

static void (*serial8250_isa_config)(int port, struct uart_port *up,
                                     u32 *capabilities);

/*
 * SERIAL_PORT_DFNS tells us about built-in ports that have no
 * standard enumeration mechanism.   Platforms that can find all
 * serial ports via mechanisms like ACPI or PCI need not supply it.
 */
#ifndef SERIAL_PORT_DFNS
#define SERIAL_PORT_DFNS
#endif

static const struct old_serial_port old_serial_port[] = {
    SERIAL_PORT_DFNS /* defined in asm/serial.h */
};

/*
 * serial8250_register_8250_port and serial8250_unregister_port allows for
 * 16x50 serial ports to be configured at run-time, to support PCMCIA
 * modems and PCI multiport cards.
 */
static DEFINE_MUTEX(serial_mutex);

#define univ8250_rsa_support(x)     do { } while (0)

static void
univ8250_console_write(struct console *co, const char *s,
                       unsigned int count)
{
#if 0
    struct uart_8250_port *up = &serial8250_ports[co->index];

    serial8250_console_write(up, s, count);
#endif
    panic("%s: END!\n", __func__);
}

static int univ8250_console_setup(struct console *co, char *options)
{
    struct uart_port *port;
    int retval;

    /*
     * Check whether an invalid uart number has been specified, and
     * if so, search for the first available port that does have
     * console support.
     */
    if (co->index >= nr_uarts)
        co->index = 0;
    port = &serial8250_ports[co->index].port;
    /* link port to console */
    port->cons = co;

    retval = serial8250_console_setup(port, options, false);
    if (retval != 0)
        port->cons = NULL;
    return retval;
}

static int univ8250_console_exit(struct console *co)
{
#if 0
    struct uart_port *port;

    port = &serial8250_ports[co->index].port;
    return serial8250_console_exit(port);
#endif
    panic("%s: END!\n", __func__);
}

struct tty_driver *uart_console_device(struct console *co, int *index)
{
    struct uart_driver *p = co->data;
    *index = co->index;
    return p->tty_driver;
}
EXPORT_SYMBOL_GPL(uart_console_device);

/**
 *  univ8250_console_match - non-standard console matching
 *  @co:      registering console
 *  @name:    name from console command line
 *  @idx:     index from console command line
 *  @options: ptr to option string from console command line
 *
 *  Only attempts to match console command lines of the form:
 *      console=uart[8250],io|mmio|mmio16|mmio32,<addr>[,<options>]
 *      console=uart[8250],0x<addr>[,<options>]
 *  This form is used to register an initial earlycon boot console and
 *  replace it with the serial8250_console at 8250 driver init.
 *
 *  Performs console setup for a match (as required by interface)
 *  If no <options> are specified, then assume the h/w is already setup.
 *
 *  Returns 0 if console matches; otherwise non-zero to use default matching
 */
static int
univ8250_console_match(struct console *co, char *name, int idx,
                       char *options)
{
    char match[] = "uart";  /* 8250-specific earlycon name */
    unsigned char iotype;
    resource_size_t addr;
    int i;

    if (strncmp(name, match, 4) != 0)
        return -ENODEV;

    if (uart_parse_earlycon(options, &iotype, &addr, &options))
        return -ENODEV;

    panic("%s: END!\n", __func__);
}

static struct console univ8250_console = {
    .name       = "ttyS",
    .write      = univ8250_console_write,
    .device     = uart_console_device,
    .setup      = univ8250_console_setup,
    .exit       = univ8250_console_exit,
    .match      = univ8250_console_match,
    .flags      = CON_PRINTBUFFER | CON_ANYTIME,
    .index      = -1,
    .data       = &serial8250_reg,
};

#define SERIAL8250_CONSOLE  (&univ8250_console)

static struct uart_driver serial8250_reg = {
    .owner          = THIS_MODULE,
    .driver_name    = "serial",
    .dev_name       = "ttyS",
    .major          = TTY_MAJOR,
    .minor          = 64,
    .cons           = SERIAL8250_CONSOLE,
};

static struct uart_8250_port *
serial8250_find_match_or_unused(const struct uart_port *port)
{
    int i;

    /*
     * First, find a port entry which matches.
     */
    for (i = 0; i < nr_uarts; i++)
        if (uart_match_port(&serial8250_ports[i].port, port))
            return &serial8250_ports[i];

    /* try line number first if still available */
    i = port->line;
    if (i < nr_uarts && serial8250_ports[i].port.type == PORT_UNKNOWN &&
        serial8250_ports[i].port.iobase == 0)
        return &serial8250_ports[i];

    panic("%s: END!\n", __func__);
}

static inline void serial8250_apply_quirks(struct uart_8250_port *up)
{
    up->port.quirks |= skip_txen_test ? UPQ_NO_TXEN_TEST : 0;
}

/**
 *  serial8250_register_8250_port - register a serial port
 *  @up: serial port template
 *
 *  Configure the serial port specified by the request. If the
 *  port exists and is in use, it is hung up and unregistered
 *  first.
 *
 *  The port is then probed and if necessary the IRQ is autodetected
 *  If this fails an error is returned.
 *
 *  On success the port is ready to use and the line number is returned.
 */
int serial8250_register_8250_port(const struct uart_8250_port *up)
{
    struct uart_8250_port *uart;
    int ret = -ENOSPC;

    if (up->port.uartclk == 0)
        return -EINVAL;

    mutex_lock(&serial_mutex);

    uart = serial8250_find_match_or_unused(&up->port);
    if (uart && uart->port.type != PORT_8250_CIR) {
        struct mctrl_gpios *gpios;

        if (uart->port.dev)
            uart_remove_one_port(&serial8250_reg, &uart->port);

        uart->port.iobase       = up->port.iobase;
        uart->port.membase      = up->port.membase;
        uart->port.irq          = up->port.irq;
        uart->port.irqflags     = up->port.irqflags;
        uart->port.uartclk      = up->port.uartclk;
        uart->port.fifosize     = up->port.fifosize;
        uart->port.regshift     = up->port.regshift;
        uart->port.iotype       = up->port.iotype;
        uart->port.flags        = up->port.flags | UPF_BOOT_AUTOCONF;
        uart->bugs              = up->bugs;
        uart->port.mapbase      = up->port.mapbase;
        uart->port.mapsize      = up->port.mapsize;
        uart->port.private_data = up->port.private_data;
        uart->tx_loadsz     = up->tx_loadsz;
        uart->capabilities  = up->capabilities;
        uart->port.throttle = up->port.throttle;
        uart->port.unthrottle   = up->port.unthrottle;
        uart->port.rs485_config = up->port.rs485_config;
        uart->port.rs485    = up->port.rs485;
        uart->rs485_start_tx    = up->rs485_start_tx;
        uart->rs485_stop_tx = up->rs485_stop_tx;
        uart->dma       = up->dma;

        /* Take tx_loadsz from fifosize if it wasn't set separately */
        if (uart->port.fifosize && !uart->tx_loadsz)
            uart->tx_loadsz = uart->port.fifosize;

        if (up->port.dev) {
            uart->port.dev = up->port.dev;
            ret = uart_get_rs485_mode(&uart->port);
            if (ret)
                goto err;
        }

        if (up->port.flags & UPF_FIXED_TYPE)
            uart->port.type = up->port.type;

#if 0
        /*
         * Only call mctrl_gpio_init(), if the device has no ACPI
         * companion device
         */
        gpios = mctrl_gpio_init(&uart->port, 0);
        if (IS_ERR(gpios)) {
            ret = PTR_ERR(gpios);
            goto err;
        } else {
            uart->gpios = gpios;
        }
#endif

        serial8250_set_defaults(uart);

        /* Possibly override default I/O functions.  */
        if (up->port.serial_in)
            uart->port.serial_in = up->port.serial_in;
        if (up->port.serial_out)
            uart->port.serial_out = up->port.serial_out;
        if (up->port.handle_irq)
            uart->port.handle_irq = up->port.handle_irq;
        /*  Possibly override set_termios call */
        if (up->port.set_termios)
            uart->port.set_termios = up->port.set_termios;
        if (up->port.set_ldisc)
            uart->port.set_ldisc = up->port.set_ldisc;
        if (up->port.get_mctrl)
            uart->port.get_mctrl = up->port.get_mctrl;
        if (up->port.set_mctrl)
            uart->port.set_mctrl = up->port.set_mctrl;
        if (up->port.get_divisor)
            uart->port.get_divisor = up->port.get_divisor;
        if (up->port.set_divisor)
            uart->port.set_divisor = up->port.set_divisor;
        if (up->port.startup)
            uart->port.startup = up->port.startup;
        if (up->port.shutdown)
            uart->port.shutdown = up->port.shutdown;
        if (up->port.pm)
            uart->port.pm = up->port.pm;
        if (up->port.handle_break)
            uart->port.handle_break = up->port.handle_break;
        if (up->dl_read)
            uart->dl_read = up->dl_read;
        if (up->dl_write)
            uart->dl_write = up->dl_write;

        if (uart->port.type != PORT_8250_CIR) {
            if (serial8250_isa_config != NULL)
                serial8250_isa_config(0, &uart->port,
                                      &uart->capabilities);

            serial8250_apply_quirks(uart);
            ret = uart_add_one_port(&serial8250_reg, &uart->port);
            if (ret)
                goto err;

            ret = uart->port.line;
        } else {
            dev_info(uart->port.dev,
                     "skipping CIR port at 0x%lx / 0x%llx, IRQ %d\n",
                     uart->port.iobase,
                     (unsigned long long)uart->port.mapbase,
                     uart->port.irq);

            ret = 0;
        }

        panic("%s: 1!\n", __func__);
    }

    panic("%s: END!\n", __func__);
    return ret;

 err:
    uart->port.dev = NULL;
    mutex_unlock(&serial_mutex);
    return ret;
}
EXPORT_SYMBOL(serial8250_register_8250_port);

/*
 * This function is used to handle ports that do not have an
 * interrupt.  This doesn't work very well for 16450's, but gives
 * barely passable results for a 16550A.  (Although at the expense
 * of much CPU overhead).
 */
static void serial8250_timeout(struct timer_list *t)
{
    struct uart_8250_port *up = from_timer(up, t, timer);

    up->port.handle_irq(&up->port);
    mod_timer(&up->timer, jiffies + uart_poll_timeout(&up->port));
}

static void __init serial8250_isa_init_ports(void)
{
    struct uart_8250_port *up;
    static int first = 1;
    int i, irqflag = 0;

    if (!first)
        return;
    first = 0;

    if (nr_uarts > UART_NR)
        nr_uarts = UART_NR;

    for (i = 0; i < nr_uarts; i++) {
        struct uart_8250_port *up = &serial8250_ports[i];
        struct uart_port *port = &up->port;

        port->line = i;
        serial8250_init_port(up);
        if (!base_ops)
            base_ops = port->ops;
        port->ops = &univ8250_port_ops;

        timer_setup(&up->timer, serial8250_timeout, 0);

        up->ops = &univ8250_driver_ops;

        serial8250_set_defaults(up);
    }

    /* chain base port ops to support Remote Supervisor Adapter */
    univ8250_port_ops = *base_ops;
    univ8250_rsa_support(&univ8250_port_ops);

    if (share_irqs)
        irqflag = IRQF_SHARED;

    for (i = 0, up = serial8250_ports;
         i < ARRAY_SIZE(old_serial_port) && i < nr_uarts;
         i++, up++) {
        struct uart_port *port = &up->port;

        port->iobase   = old_serial_port[i].port;
        port->irq      = irq_canonicalize(old_serial_port[i].irq);
        port->irqflags = 0;
        port->uartclk  = old_serial_port[i].baud_base * 16;
        port->flags    = old_serial_port[i].flags;
        port->hub6     = 0;
        port->membase  = old_serial_port[i].iomem_base;
        port->iotype   = old_serial_port[i].io_type;
        port->regshift = old_serial_port[i].iomem_reg_shift;

        port->irqflags |= irqflag;
        if (serial8250_isa_config != NULL)
            serial8250_isa_config(i, &up->port, &up->capabilities);
        panic("%s: 1!\n", __func__);
    }
}

/*
 * early_serial_setup - early registration for 8250 ports
 *
 * Setup an 8250 port structure prior to console initialisation.  Use
 * after console initialisation will cause undefined behaviour.
 */
int __init early_serial_setup(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static void __init
serial8250_register_ports(struct uart_driver *drv, struct device *dev)
{
    int i;

    for (i = 0; i < nr_uarts; i++) {
        struct uart_8250_port *up = &serial8250_ports[i];

        if (up->port.type == PORT_8250_CIR)
            continue;

        if (up->port.dev)
            continue;

        up->port.dev = dev;

        serial8250_apply_quirks(up);
        uart_add_one_port(drv, &up->port);
    }
}

/*
 * Register a set of serial devices attached to a platform device.  The
 * list is terminated with a zero flags entry, which means we expect
 * all entries to have at least UPF_BOOT_AUTOCONF set.
 */
static int serial8250_probe(struct platform_device *dev)
{
    struct plat_serial8250_port *p = dev_get_platdata(&dev->dev);
    struct uart_8250_port uart;
    int ret, i, irqflag = 0;

    printk("###### %s: 1 ...\n", __func__);

    memset(&uart, 0, sizeof(uart));

    if (share_irqs)
        irqflag = IRQF_SHARED;

    for (i = 0; p && p->flags != 0; p++, i++) {
        uart.port.iobase    = p->iobase;
        uart.port.membase   = p->membase;
        uart.port.irq       = p->irq;
        uart.port.irqflags  = p->irqflags;
        uart.port.uartclk   = p->uartclk;
        uart.port.regshift  = p->regshift;
        uart.port.iotype    = p->iotype;
        uart.port.flags     = p->flags;
        uart.port.mapbase   = p->mapbase;
        uart.port.hub6      = p->hub6;
        uart.port.has_sysrq = p->has_sysrq;
        uart.port.private_data  = p->private_data;
        uart.port.type      = p->type;
        uart.port.serial_in = p->serial_in;
        uart.port.serial_out    = p->serial_out;
        uart.port.handle_irq    = p->handle_irq;
        uart.port.handle_break  = p->handle_break;
        uart.port.set_termios   = p->set_termios;
        uart.port.set_ldisc = p->set_ldisc;
        uart.port.get_mctrl = p->get_mctrl;
        uart.port.pm        = p->pm;
        uart.port.dev       = &dev->dev;
        uart.port.irqflags  |= irqflag;
        ret = serial8250_register_8250_port(&uart);
        if (ret < 0) {
            dev_err(&dev->dev, "unable to register port at index %d "
                    "(IO%lx MEM%llx IRQ%d): %d\n", i,
                    p->iobase, (unsigned long long)p->mapbase,
                    p->irq, ret);
        }
    }
    return 0;
}

/*
 * Remove serial ports registered against a platform device.
 */
static int serial8250_remove(struct platform_device *dev)
{
    panic("%s: END!\n", __func__);
}

static int serial8250_suspend(struct platform_device *dev,
                              pm_message_t state)
{
    panic("%s: END!\n", __func__);
}

static int serial8250_resume(struct platform_device *dev)
{
    panic("%s: END!\n", __func__);
}

static struct platform_driver serial8250_isa_driver = {
    .probe      = serial8250_probe,
    .remove     = serial8250_remove,
    .suspend    = serial8250_suspend,
    .resume     = serial8250_resume,
    .driver     = {
        .name   = "serial8250",
    },
};

static int __init serial8250_init(void)
{
    int ret;

    if (nr_uarts == 0)
        return -ENODEV;

    serial8250_isa_init_ports();

    pr_info("Serial: 8250/16550 driver, %d ports, "
            "IRQ sharing %sabled\n",
            nr_uarts, share_irqs ? "en" : "dis");

    serial8250_reg.nr = UART_NR;
    ret = uart_register_driver(&serial8250_reg);
    if (ret)
        goto out;

    ret = serial8250_pnp_init();
    if (ret)
        goto unreg_uart_drv;

    serial8250_isa_devs = platform_device_alloc("serial8250",
                                                PLAT8250_DEV_LEGACY);
    if (!serial8250_isa_devs) {
        ret = -ENOMEM;
        goto unreg_pnp;
    }

    ret = platform_device_add(serial8250_isa_devs);
    if (ret)
        goto put_dev;

    serial8250_register_ports(&serial8250_reg,
                              &serial8250_isa_devs->dev);

    ret = platform_driver_register(&serial8250_isa_driver);
    if (ret == 0)
        goto out;

    panic("%s: END!\n", __func__);

    platform_device_del(serial8250_isa_devs);
 put_dev:
    platform_device_put(serial8250_isa_devs);
 unreg_pnp:
    serial8250_pnp_exit();
 unreg_uart_drv:
    uart_unregister_driver(&serial8250_reg);
 out:
    return ret;
}

static void __exit serial8250_exit(void)
{
    panic("%s: END!\n", __func__);
}

module_init(serial8250_init);
module_exit(serial8250_exit);

static int __init univ8250_console_init(void)
{
    if (nr_uarts == 0)
        return -ENODEV;

    serial8250_isa_init_ports();
    register_console(&univ8250_console);
    return 0;
}
console_initcall(univ8250_console_init);

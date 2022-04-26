// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2014 Linaro Ltd.
 * Author: Rob Herring <robh@kernel.org>
 *
 * Based on 8250 earlycon:
 * (c) Copyright 2004 Hewlett-Packard Development Company, L.P.
 *  Bjorn Helgaas <bjorn.helgaas@hp.com>
 */

#define pr_fmt(fmt)     KBUILD_MODNAME ": " fmt

#include <linux/console.h>
#include <linux/kernel.h>
#include <linux/init.h>
//#include <linux/io.h>
#include <linux/serial_core.h>
#include <linux/sizes.h>
//#include <linux/of.h>
#include <linux/of_fdt.h>
//#include <linux/acpi.h>
#include <linux/string.h>
#include <linux/errno.h>

#ifdef CONFIG_FIX_EARLYCON_MEM
#include <asm/fixmap.h>
#endif

//#include <asm/serial.h>

static struct console early_con = {
    .name =     "uart",     /* fixed up at earlycon registration */
    .flags =    CON_PRINTBUFFER | CON_BOOT,
    .index =    0,
};

static struct earlycon_device early_console_dev = {
    .con = &early_con,
};

static void __init
earlycon_init(struct earlycon_device *device, const char *name)
{
    struct console *earlycon = device->con;
    //struct uart_port *port = &device->port;
    const char *s;
    size_t len;

    /* scan backwards from end of string for first non-numeral */
    for (s = name + strlen(name);
         s > name && s[-1] >= '0' && s[-1] <= '9';
         s--)
        ;
    if (*s)
        earlycon->index = simple_strtoul(s, NULL, 10);
    len = s - name;
    strlcpy(earlycon->name, name, min(len + 1, sizeof(earlycon->name)));
    earlycon->data = &early_console_dev;

#if 0
    if (port->iotype == UPIO_MEM || port->iotype == UPIO_MEM16 ||
        port->iotype == UPIO_MEM32 || port->iotype == UPIO_MEM32BE)
        pr_info("%s%d at MMIO%s %pa (options '%s')\n",
            earlycon->name, earlycon->index,
            (port->iotype == UPIO_MEM) ? "" :
            (port->iotype == UPIO_MEM16) ? "16" :
            (port->iotype == UPIO_MEM32) ? "32" : "32be",
            &port->mapbase, device->options);
    else
        pr_info("%s%d at I/O port 0x%lx (options '%s')\n",
            earlycon->name, earlycon->index,
            port->iobase, device->options);
#endif
}

static int __init
register_earlycon(char *buf, const struct earlycon_id *match)
{
    int err;
#if 0
    struct uart_port *port = &early_console_dev.port;

    /* On parsing error, pass the options buf to the setup function */
    if (buf && !parse_options(&early_console_dev, buf))
        buf = NULL;

    spin_lock_init(&port->lock);
    port->uartclk = BASE_BAUD * 16;
    if (port->mapbase)
        port->membase = earlycon_map(port->mapbase, 64);
#endif

    earlycon_init(&early_console_dev, match->name);
    err = match->setup(&early_console_dev, buf);
    if (err < 0)
        return err;
    if (!early_console_dev.con->write)
        return -ENODEV;

    register_console(early_console_dev.con);
    return 0;
}

int __init setup_earlycon(char *buf)
{
    const struct earlycon_id **p_match;
    bool empty_compatible = true;

    if (!buf || !buf[0])
        return -EINVAL;

    if (early_con.flags & CON_ENABLED)
        return -EALREADY;

again:
    for (p_match = __earlycon_table; p_match < __earlycon_table_end;
         p_match++) {
        const struct earlycon_id *match = *p_match;
        size_t len = strlen(match->name);

        if (strncmp(buf, match->name, len))
            continue;

        /* prefer entries with empty compatible */
        if (empty_compatible && *match->compatible)
            continue;

        if (buf[len]) {
            if (buf[len] != ',')
                continue;
            buf += len + 1;
        } else
            buf = NULL;

        return register_earlycon(buf, match);
    }

    if (empty_compatible) {
        empty_compatible = false;
        goto again;
    }

    return -ENOENT;
}

/* early_param wrapper for setup_earlycon() */
static int __init param_setup_earlycon(char *buf)
{
    int err;

    /* Just 'earlycon' is a valid param for devicetree and ACPI SPCR. */
    if (!buf || !buf[0])
        panic("no param value for earlycon!");

    err = setup_earlycon(buf);
    if (err == -ENOENT || err == -EALREADY)
        return 0;
    return err;
}
early_param("earlycon", param_setup_earlycon);

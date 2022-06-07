/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  linux/drivers/char/serial_core.h
 *
 *  Copyright (C) 2000 Deep Blue Solutions Ltd.
 */
#ifndef LINUX_SERIAL_CORE_H
#define LINUX_SERIAL_CORE_H

#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/console.h>
//#include <linux/interrupt.h>
//#include <linux/circ_buf.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
//#include <linux/tty.h>
#include <linux/mutex.h>
//#include <linux/sysrq.h>
//#include <uapi/linux/serial_core.h>

#define EARLYCON_USED_OR_UNUSED __used

#define OF_EARLYCON_DECLARE(_name, compat, fn) \
static const struct earlycon_id __UNIQUE_ID(__earlycon_##_name) \
EARLYCON_USED_OR_UNUSED __section("__earlycon_table")   \
__aligned(__alignof__(struct earlycon_id)) = { \
    .name = __stringify(_name), \
    .compatible = compat,       \
    .setup = fn                 \
}

#define EARLYCON_DECLARE(_name, fn) OF_EARLYCON_DECLARE(_name, "", fn)

struct uart_port {
};

/*
 * Console helpers.
 */
struct earlycon_device {
    struct console *con;
    struct uart_port port;
    char options[16];       /* e.g., 115200n8 */
    unsigned int baud;
};

struct earlycon_id {
    char name[15];
    char name_term;  /* In case compiler didn't '\0' term name */
    char compatible[128];
    int (*setup)(struct earlycon_device *, const char *options);
};

extern const struct earlycon_id __earlycon_table[];
extern const struct earlycon_id __earlycon_table_end[];

int setup_earlycon(char *buf);

void uart_console_write(struct uart_port *port,
                        const char *s, unsigned int count,
                        void (*putchar)(struct uart_port *, int));

extern int
of_setup_earlycon(const struct earlycon_id *match,
                  unsigned long node, const char *options);

#endif /* LINUX_SERIAL_CORE_H */

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
//#include <linux/mutex.h>
//#include <linux/sysrq.h>
//#include <uapi/linux/serial_core.h>

#define EARLYCON_USED_OR_UNUSED __used

#define _OF_EARLYCON_DECLARE(_name, compat, fn, unique_id)  \
static const struct earlycon_id unique_id \
EARLYCON_USED_OR_UNUSED __initconst = { \
    .name = __stringify(_name), \
    .compatible = compat,       \
    .setup = fn                 \
}; \
static const struct earlycon_id EARLYCON_USED_OR_UNUSED \
__section(__earlycon_table) * const \
__PASTE(__p, unique_id) = &unique_id

#define OF_EARLYCON_DECLARE(_name, compat, fn) \
    _OF_EARLYCON_DECLARE(_name, compat, fn, \
                         __UNIQUE_ID(__earlycon_##_name))

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

extern const struct earlycon_id *__earlycon_table[];
extern const struct earlycon_id *__earlycon_table_end[];

int setup_earlycon(char *buf);

#endif /* LINUX_SERIAL_CORE_H */

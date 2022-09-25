/*
 *  linux/include/linux/console.h
 *
 *  Copyright (C) 1993        Hamish Macdonald
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * Changed:
 * 10-Mar-94: Arno Griffioen: Conversion for vt100 emulator port from PC LINUX
 */

#ifndef _LINUX_CONSOLE_H_
#define _LINUX_CONSOLE_H_

#include <linux/atomic.h>
#include <linux/types.h>

/*
 * The interface for a console, or any other device that wants to capture
 * console messages (printer driver?)
 *
 * If a console driver is marked CON_BOOT then it will be auto-unregistered
 * when the first real console is registered.  This is for early-printk drivers.
 */

#define CON_PRINTBUFFER (1)
#define CON_CONSDEV     (2)     /* Preferred console, /dev/console */
#define CON_ENABLED     (4)
#define CON_BOOT        (8)
#define CON_ANYTIME     (16)    /* Safe to call when cpu is offline */
#define CON_BRL         (32)    /* Used for a braille device */
#define CON_EXTENDED    (64)    /* Use the extended output format a la /dev/kmsg */

struct console {
    char    name[16];

    void    (*write)(struct console *, const char *, unsigned);
    int     (*read)(struct console *, char *, unsigned);
    struct tty_driver *(*device)(struct console *, int *);
    void    (*unblank)(void);
    int     (*setup)(struct console *, char *);
    int     (*exit)(struct console *);
    int     (*match)(struct console *, char *name, int idx, char *options);

    short   flags;
    short   index;
    int     cflag;
    void    *data;

    struct console *next;
};

/*
 * for_each_console() allows you to iterate on each console
 */
#define for_each_console(con) \
    for (con = console_drivers; con != NULL; con = con->next)

extern struct console *console_drivers;

extern void register_console(struct console *);
extern int unregister_console(struct console *);

extern int console_set_on_cmdline;

extern int add_preferred_console(char *name, int idx, char *options);

#endif /* _LINUX_CONSOLE_H_ */

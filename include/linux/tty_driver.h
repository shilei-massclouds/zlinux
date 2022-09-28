/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TTY_DRIVER_H
#define _LINUX_TTY_DRIVER_H

#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/termios.h>
#if 0
#include <linux/seq_file.h>
#endif

struct tty_struct;
struct tty_driver;
struct serial_icounter_struct;
struct serial_struct;

/**
 * struct tty_driver -- driver for TTY devices
 *
 * @magic: set to %TTY_DRIVER_MAGIC in __tty_alloc_driver()
 * @kref: reference counting. Reaching zero frees all the internals and the
 *    driver.
 * @cdevs: allocated/registered character /dev devices
 * @owner: modules owning this driver. Used drivers cannot be rmmod'ed.
 *     Automatically set by tty_alloc_driver().
 * @driver_name: name of the driver used in /proc/tty
 * @name: used for constructing /dev node name
 * @name_base: used as a number base for constructing /dev node name
 * @major: major /dev device number (zero for autoassignment)
 * @minor_start: the first minor /dev device number
 * @num: number of devices allocated
 * @type: type of tty driver (%TTY_DRIVER_TYPE_)
 * @subtype: subtype of tty driver (%SYSTEM_TYPE_, %PTY_TYPE_, %SERIAL_TYPE_)
 * @init_termios: termios to set to each tty initially (e.g. %tty_std_termios)
 * @flags: tty driver flags (%TTY_DRIVER_)
 * @proc_entry: proc fs entry, used internally
 * @other: driver of the linked tty; only used for the PTY driver
 * @ttys: array of active &struct tty_struct, set by tty_standard_install()
 * @ports: array of &struct tty_port; can be set during initialization by
 *     tty_port_link_device() and similar
 * @termios: storage for termios at each TTY close for the next open
 * @driver_state: pointer to driver's arbitrary data
 * @ops: driver hooks for TTYs. Set them using tty_set_operations(). Use &struct
 *   tty_port helpers in them as much as possible.
 * @tty_drivers: used internally to link tty_drivers together
 *
 * The usual handling of &struct tty_driver is to allocate it by
 * tty_alloc_driver(), set up all the necessary members, and register it by
 * tty_register_driver(). At last, the driver is torn down by calling
 * tty_unregister_driver() followed by tty_driver_kref_put().
 *
 * The fields required to be set before calling tty_register_driver() include
 * @driver_name, @name, @type, @subtype, @init_termios, and @ops.
 */
struct tty_driver {
    int magic;
    struct kref kref;
    struct cdev **cdevs;
    struct module   *owner;
    const char  *driver_name;
    const char  *name;
    int name_base;
    int major;
    int minor_start;
    unsigned int    num;
    short   type;
    short   subtype;
    struct ktermios init_termios;
    unsigned long   flags;
    struct proc_dir_entry *proc_entry;
    struct tty_driver *other;

    /*
     * Pointer to the tty data structures
     */
    struct tty_struct **ttys;
    struct tty_port **ports;
    struct ktermios **termios;
    void *driver_state;

    /*
     * Driver methods
     */

    const struct tty_operations *ops;
    struct list_head tty_drivers;
} __randomize_layout;

struct tty_driver *
__tty_alloc_driver(unsigned int lines, struct module *owner,
                   unsigned long flags);

/* Use TTY_DRIVER_* flags below */
#define tty_alloc_driver(lines, flags) \
        __tty_alloc_driver(lines, THIS_MODULE, flags)

/* tty driver magic number */
#define TTY_DRIVER_MAGIC        0x5402

/**
 * DOC: TTY Driver Flags
 *
 * TTY_DRIVER_RESET_TERMIOS
 *  Requests the tty layer to reset the termios setting when the last
 *  process has closed the device. Used for PTYs, in particular.
 *
 * TTY_DRIVER_REAL_RAW
 *  Indicates that the driver will guarantee not to set any special
 *  character handling flags if this is set for the tty:
 *
 *  ``(IGNBRK || (!BRKINT && !PARMRK)) && (IGNPAR || !INPCK)``
 *
 *  That is, if there is no reason for the driver to
 *  send notifications of parity and break characters up to the line
 *  driver, it won't do so.  This allows the line driver to optimize for
 *  this case if this flag is set.  (Note that there is also a promise, if
 *  the above case is true, not to signal overruns, either.)
 *
 * TTY_DRIVER_DYNAMIC_DEV
 *  The individual tty devices need to be registered with a call to
 *  tty_register_device() when the device is found in the system and
 *  unregistered with a call to tty_unregister_device() so the devices will
 *  be show up properly in sysfs.  If not set, all &tty_driver.num entries
 *  will be created by the tty core in sysfs when tty_register_driver() is
 *  called.  This is to be used by drivers that have tty devices that can
 *  appear and disappear while the main tty driver is registered with the
 *  tty core.
 *
 * TTY_DRIVER_DEVPTS_MEM
 *  Don't use the standard arrays (&tty_driver.ttys and
 *  &tty_driver.termios), instead use dynamic memory keyed through the
 *  devpts filesystem. This is only applicable to the PTY driver.
 *
 * TTY_DRIVER_HARDWARE_BREAK
 *  Hardware handles break signals. Pass the requested timeout to the
 *  &tty_operations.break_ctl instead of using a simple on/off interface.
 *
 * TTY_DRIVER_DYNAMIC_ALLOC
 *  Do not allocate structures which are needed per line for this driver
 *  (&tty_driver.ports) as it would waste memory. The driver will take
 *  care. This is only applicable to the PTY driver.
 *
 * TTY_DRIVER_UNNUMBERED_NODE
 *  Do not create numbered ``/dev`` nodes. For example, create
 *  ``/dev/ttyprintk`` and not ``/dev/ttyprintk0``. Applicable only when a
 *  driver for a single tty device is being allocated.
 */
#define TTY_DRIVER_INSTALLED        0x0001
#define TTY_DRIVER_RESET_TERMIOS    0x0002
#define TTY_DRIVER_REAL_RAW         0x0004
#define TTY_DRIVER_DYNAMIC_DEV      0x0008
#define TTY_DRIVER_DEVPTS_MEM       0x0010
#define TTY_DRIVER_HARDWARE_BREAK   0x0020
#define TTY_DRIVER_DYNAMIC_ALLOC    0x0040
#define TTY_DRIVER_UNNUMBERED_NODE  0x0080

static inline
void tty_set_operations(struct tty_driver *driver,
                        const struct tty_operations *op)
{
    driver->ops = op;
}

/* serial subtype definitions */
#define SERIAL_TYPE_NORMAL  1

struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
                                  struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
                  const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    unsigned int (*write_room)(struct tty_struct *tty);
    unsigned int (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
                  unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                         unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
                    unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*get_icount)(struct tty_struct *tty,
                      struct serial_icounter_struct *icount);
    int  (*get_serial)(struct tty_struct *tty, struct serial_struct *p);
    int  (*set_serial)(struct tty_struct *tty, struct serial_struct *p);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
    int (*proc_show)(struct seq_file *m, void *driver);
} __randomize_layout;

/* tty driver types */
#define TTY_DRIVER_TYPE_SYSTEM      0x0001
#define TTY_DRIVER_TYPE_CONSOLE     0x0002
#define TTY_DRIVER_TYPE_SERIAL      0x0003
#define TTY_DRIVER_TYPE_PTY         0x0004
#define TTY_DRIVER_TYPE_SCC         0x0005  /* scc driver */
#define TTY_DRIVER_TYPE_SYSCONS     0x0006

int tty_register_driver(struct tty_driver *driver);

void tty_driver_kref_put(struct tty_driver *driver);

struct device *
tty_register_device_attr(struct tty_driver *driver,
                         unsigned index, struct device *device,
                         void *drvdata,
                         const struct attribute_group **attr_grp);

/* pty subtypes (magic, used by tty_io.c) */
#define PTY_TYPE_MASTER         0x0001
#define PTY_TYPE_SLAVE          0x0002

void tty_unregister_device(struct tty_driver *driver, unsigned index);

static inline
struct tty_driver *tty_driver_kref_get(struct tty_driver *d)
{
    kref_get(&d->kref);
    return d;
}

#endif /* #ifdef _LINUX_TTY_DRIVER_H */

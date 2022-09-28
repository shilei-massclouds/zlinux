// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

/*
 * 'tty_io.c' gives an orthogonal feeling to tty's, be they consoles
 * or rs-channels. It also implements echoing, cooked mode etc.
 *
 * Kill-line thanks to John T Kohl, who also corrected VMIN = VTIME = 0.
 *
 * Modified by Theodore Ts'o, 9/14/92, to dynamically allocate the
 * tty_struct and tty_queue structures.  Previously there was an array
 * of 256 tty_struct's which was statically allocated, and the
 * tty_queue structures were allocated at boot time.  Both are now
 * dynamically allocated only when the tty is open.
 *
 * Also restructured routines so that there is more of a separation
 * between the high-level tty routines (tty_io.c and tty_ioctl.c) and
 * the low-level tty routines (serial.c, pty.c, console.c).  This
 * makes for cleaner and more compact code.  -TYT, 9/17/92
 *
 * Modified by Fred N. van Kempen, 01/29/93, to add line disciplines
 * which can be dynamically activated and de-activated by the line
 * discipline handling modules (like SLIP).
 *
 * NOTE: pay no attention to the line discipline code (yet); its
 * interface is still subject to change in this version...
 * -- TYT, 1/31/92
 */

#include <linux/types.h>
#include <linux/major.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/fcntl.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#if 0
#include <linux/tty_flip.h>
#include <linux/devpts_fs.h>
#endif
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/console.h>
#include <linux/timer.h>
#include <linux/ctype.h>
//#include <linux/kd.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/poll.h>
//#include <linux/ppp-ioctl.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/delay.h>
//#include <linux/seq_file.h>
#include <linux/serial.h>
#include <linux/ratelimit.h>
#include <linux/compat.h>

#include <linux/uaccess.h>

//#include <linux/kbd_kern.h>
#include <linux/vt_kern.h>
//#include <linux/selection.h>

#include <linux/kmod.h>
#include <linux/nsproxy.h>
#include "tty.h"

static const struct file_operations tty_fops;

struct class *tty_class;

/* Mutex to protect creating and releasing a tty */
DEFINE_MUTEX(tty_mutex);

/* This list gets poked at by procfs and various bits of boot up code.
 * This could do with some rationalisation such as pulling
 * the tty proc function into this file.
 */

LIST_HEAD(tty_drivers);         /* linked list of tty drivers */

/* 3/2004 jmc: why do these devices exist? */
static struct cdev tty_cdev, console_cdev;

static void tty_device_create_release(struct device *dev)
{
    dev_dbg(dev, "releasing...\n");
    kfree(dev);
}

dev_t tty_devnum(struct tty_struct *tty)
{
    return MKDEV(tty->driver->major,
                 tty->driver->minor_start) + tty->index;
}
EXPORT_SYMBOL(tty_devnum);

/* Must put_device() after it's unused! */
static struct device *tty_get_device(struct tty_struct *tty)
{
    dev_t devt = tty_devnum(tty);

    return class_find_device_by_devt(tty_class, devt);
}

/**
 * __tty_alloc_driver -- allocate tty driver
 * @lines: count of lines this driver can handle at most
 * @owner: module which is responsible for this driver
 * @flags: some of %TTY_DRIVER_ flags, will be set in driver->flags
 *
 * This should not be called directly, some of the provided macros should be
 * used instead. Use IS_ERR() and friends on @retval.
 */
struct tty_driver *
__tty_alloc_driver(unsigned int lines, struct module *owner,
                   unsigned long flags)
{
    struct tty_driver *driver;
    unsigned int cdevs = 1;
    int err;

    if (!lines || (flags & TTY_DRIVER_UNNUMBERED_NODE && lines > 1))
        return ERR_PTR(-EINVAL);

    driver = kzalloc(sizeof(*driver), GFP_KERNEL);
    if (!driver)
        return ERR_PTR(-ENOMEM);

    kref_init(&driver->kref);
    driver->magic = TTY_DRIVER_MAGIC;
    driver->num = lines;
    driver->owner = owner;
    driver->flags = flags;

    if (!(flags & TTY_DRIVER_DEVPTS_MEM)) {
        driver->ttys = kcalloc(lines, sizeof(*driver->ttys),
                GFP_KERNEL);
        driver->termios = kcalloc(lines, sizeof(*driver->termios),
                GFP_KERNEL);
        if (!driver->ttys || !driver->termios) {
            err = -ENOMEM;
            goto err_free_all;
        }
    }

    if (!(flags & TTY_DRIVER_DYNAMIC_ALLOC)) {
        driver->ports = kcalloc(lines, sizeof(*driver->ports),
                GFP_KERNEL);
        if (!driver->ports) {
            err = -ENOMEM;
            goto err_free_all;
        }
        cdevs = lines;
    }

    driver->cdevs = kcalloc(cdevs, sizeof(*driver->cdevs), GFP_KERNEL);
    if (!driver->cdevs) {
        err = -ENOMEM;
        goto err_free_all;
    }

    return driver;

 err_free_all:
    kfree(driver->ports);
    kfree(driver->ttys);
    kfree(driver->termios);
    kfree(driver->cdevs);
    kfree(driver);
    return ERR_PTR(err);
}

struct ktermios tty_std_termios = {
    /* for the benefit of tty drivers  */
    .c_iflag = ICRNL | IXON,
    .c_oflag = OPOST | ONLCR,
    .c_cflag = B38400 | CS8 | CREAD | HUPCL,
    .c_lflag = ISIG | ICANON | ECHO | ECHOE | ECHOK |
        ECHOCTL | ECHOKE | IEXTEN,
    .c_cc = INIT_C_CC,
    .c_ispeed = 38400,
    .c_ospeed = 38400,
    /* .c_line = N_TTY, */
};
EXPORT_SYMBOL(tty_std_termios);

static void destruct_tty_driver(struct kref *kref)
{
    panic("%s: END!\n", __func__);
}

/**
 * tty_driver_kref_put -- drop a reference to a tty driver
 * @driver: driver of which to drop the reference
 *
 * The final put will destroy and free up the driver.
 */
void tty_driver_kref_put(struct tty_driver *driver)
{
    kref_put(&driver->kref, destruct_tty_driver);
}
EXPORT_SYMBOL(tty_driver_kref_put);

/**
 * tty_unregister_device - unregister a tty device
 * @driver: the tty driver that describes the tty device
 * @index: the index in the tty driver for this tty device
 *
 * If a tty device is registered with a call to tty_register_device() then
 * this function must be called when the tty device is gone.
 *
 * Locking: ??
 */
void tty_unregister_device(struct tty_driver *driver, unsigned index)
{
    device_destroy(tty_class,
                   MKDEV(driver->major, driver->minor_start) + index);
    if (!(driver->flags & TTY_DRIVER_DYNAMIC_ALLOC)) {
        cdev_del(driver->cdevs[index]);
        driver->cdevs[index] = NULL;
    }
}

/**
 * pty_line_name    -   generate name for a pty
 * @driver: the tty driver in use
 * @index: the minor number
 * @p: output buffer of at least 6 bytes
 *
 * Generate a name from a @driver reference and write it to the output buffer
 * @p.
 *
 * Locking: None
 */
static void pty_line_name(struct tty_driver *driver, int index, char *p)
{
    static const char ptychar[] = "pqrstuvwxyzabcde";
    int i = index + driver->name_base;
    /* ->name is initialized to "ttyp", but "tty" is expected */
    sprintf(p, "%s%c%x",
            driver->subtype == PTY_TYPE_SLAVE ? "tty" : driver->name,
            ptychar[i >> 4 & 0xf], i & 0xf);
}

/**
 * tty_line_name    -   generate name for a tty
 * @driver: the tty driver in use
 * @index: the minor number
 * @p: output buffer of at least 7 bytes
 *
 * Generate a name from a @driver reference and write it to the output buffer
 * @p.
 *
 * Locking: None
 */
static ssize_t tty_line_name(struct tty_driver *driver, int index,
                             char *p)
{
    if (driver->flags & TTY_DRIVER_UNNUMBERED_NODE)
        return sprintf(p, "%s", driver->name);
    else
        return sprintf(p, "%s%d", driver->name,
                       index + driver->name_base);
}

/**
 * tty_read -   read method for tty device files
 * @iocb: kernel I/O control block
 * @to: destination for the data read
 *
 * Perform the read system call function on this terminal device. Checks
 * for hung up devices before calling the line discipline method.
 *
 * Locking:
 *  Locks the line discipline internally while needed. Multiple read calls
 *  may be outstanding in parallel.
 */
static ssize_t tty_read(struct kiocb *iocb, struct iov_iter *to)
{
    panic("%s: END!\n", __func__);
}

/**
 * tty_write        -   write method for tty device file
 * @iocb: kernel I/O control block
 * @from: iov_iter with data to write
 *
 * Write data to a tty device via the line discipline.
 *
 * Locking:
 *  Locks the line discipline as required
 *  Writes to the tty driver are serialized by the atomic_write_lock
 *  and are then processed in chunks to the device. The line
 *  discipline write method will not be invoked in parallel for
 *  each device.
 */
static ssize_t tty_write(struct kiocb *iocb, struct iov_iter *from)
{
    panic("%s: END!\n", __func__);
}

ssize_t redirected_tty_write(struct kiocb *iocb, struct iov_iter *iter)
{
    panic("%s: END!\n", __func__);
}

/**
 * tty_poll -   check tty status
 * @filp: file being polled
 * @wait: poll wait structures to update
 *
 * Call the line discipline polling method to obtain the poll status of the
 * device.
 *
 * Locking: locks called line discipline but ldisc poll method may be
 * re-entered freely by other callers.
 */
static __poll_t tty_poll(struct file *filp, poll_table *wait)
{
    panic("%s: END!\n", __func__);
}

/*
 * Split this up, as gcc can choke on it otherwise..
 */
long tty_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    panic("%s: END!\n", __func__);
}

static long tty_compat_ioctl(struct file *file, unsigned int cmd,
                             unsigned long arg)
{
    panic("%s: END!\n", __func__);
}

int tty_alloc_file(struct file *file)
{
    struct tty_file_private *priv;

    priv = kmalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv)
        return -ENOMEM;

    file->private_data = priv;

    return 0;
}

/**
 * tty_open_current_tty - get locked tty of current task
 * @device: device number
 * @filp: file pointer to tty
 * @return: locked tty of the current task iff @device is /dev/tty
 *
 * Performs a re-open of the current task's controlling tty.
 *
 * We cannot return driver and index like for the other nodes because devpts
 * will not work then. It expects inodes to be from devpts FS.
 */
static struct tty_struct *
tty_open_current_tty(dev_t device, struct file *filp)
{
    struct tty_struct *tty;
    int retval;

    if (device != MKDEV(TTYAUX_MAJOR, 0))
        return NULL;

    tty = get_current_tty();
    if (!tty)
        return ERR_PTR(-ENXIO);

    panic("%s: END!\n", __func__);
}

/**
 * get_tty_driver       -   find device of a tty
 * @device: device identifier
 * @index: returns the index of the tty
 *
 * This routine returns a tty driver structure, given a device number and also
 * passes back the index number.
 *
 * Locking: caller must hold tty_mutex
 */
static struct tty_driver *get_tty_driver(dev_t device, int *index)
{
    struct tty_driver *p;

    list_for_each_entry(p, &tty_drivers, tty_drivers) {
        dev_t base = MKDEV(p->major, p->minor_start);

        if (device < base || device >= base + p->num)
            continue;
        *index = device - base;
        return tty_driver_kref_get(p);
    }
    return NULL;
}

/**
 * tty_lookup_driver - lookup a tty driver for a given device file
 * @device: device number
 * @filp: file pointer to tty
 * @index: index for the device in the @return driver
 *
 * If returned value is not erroneous, the caller is responsible to decrement
 * the refcount by tty_driver_kref_put().
 *
 * Locking: %tty_mutex protects get_tty_driver()
 *
 * Return: driver for this inode (with increased refcount)
 */
static struct tty_driver *
tty_lookup_driver(dev_t device, struct file *filp, int *index)
{
    struct tty_driver *driver = NULL;

    switch (device) {
    case MKDEV(TTY_MAJOR, 0): {
        extern struct tty_driver *console_driver;

        driver = tty_driver_kref_get(console_driver);
        *index = fg_console;
        break;
    }
    case MKDEV(TTYAUX_MAJOR, 1): {
        struct tty_driver *console_driver = console_device(index);

        if (console_driver) {
            driver = tty_driver_kref_get(console_driver);
            if (driver && filp) {
                /* Don't let /dev/console block */
                filp->f_flags |= O_NONBLOCK;
                break;
            }
        }
        if (driver)
            tty_driver_kref_put(driver);
        return ERR_PTR(-ENODEV);
    }
    default:
        driver = get_tty_driver(device, index);
        if (!driver)
            return ERR_PTR(-ENODEV);
        break;
    }
    return driver;
}

/**
 * tty_driver_lookup_tty() - find an existing tty, if any
 * @driver: the driver for the tty
 * @file: file object
 * @idx: the minor number
 *
 * Return: the tty, if found. If not found, return %NULL or ERR_PTR() if the
 * driver lookup() method returns an error.
 *
 * Locking: tty_mutex must be held. If the tty is found, bump the tty kref.
 */
static struct tty_struct *
tty_driver_lookup_tty(struct tty_driver *driver, struct file *file,
                      int idx)
{
    struct tty_struct *tty;

    if (driver->ops->lookup)
        if (!file)
            tty = ERR_PTR(-EIO);
        else
            tty = driver->ops->lookup(driver, file, idx);
    else
        tty = driver->ttys[idx];

    if (!IS_ERR(tty))
        tty_kref_get(tty);
    return tty;
}

/**
 * release_tty      -   release tty structure memory
 * @tty: tty device release
 * @idx: index of the tty device release
 *
 * Release both @tty and a possible linked partner (think pty pair),
 * and decrement the refcount of the backing module.
 *
 * Locking:
 *  tty_mutex
 *  takes the file list lock internally when working on the list of ttys
 *  that the driver keeps.
 */
static void release_tty(struct tty_struct *tty, int idx)
{
#if 0
    /* This should always be true but check for the moment */
    WARN_ON(tty->index != idx);
    WARN_ON(!mutex_is_locked(&tty_mutex));
    if (tty->ops->shutdown)
        tty->ops->shutdown(tty);
    tty_save_termios(tty);
    tty_driver_remove_tty(tty->driver, tty);
    if (tty->port)
        tty->port->itty = NULL;
    if (tty->link)
        tty->link->port->itty = NULL;
    if (tty->port)
        tty_buffer_cancel_work(tty->port);
    if (tty->link)
        tty_buffer_cancel_work(tty->link->port);

    tty_kref_put(tty->link);
    tty_kref_put(tty);
#endif
    panic("%s: END!\n", __func__);
}

/**
 * free_tty_struct  -   free a disused tty
 * @tty: tty struct to free
 *
 * Free the write buffers, tty queue and tty memory itself.
 *
 * Locking: none. Must be called after tty is definitely unused
 */
static void free_tty_struct(struct tty_struct *tty)
{
    tty_ldisc_deinit(tty);
    put_device(tty->dev);
    kvfree(tty->write_buf);
    tty->magic = 0xDEADDEAD;
    kfree(tty);
}

const char *tty_driver_name(const struct tty_struct *tty)
{
    if (!tty || !tty->driver)
        return "";
    return tty->driver->name;
}

static void do_tty_hangup(struct work_struct *work)
{
    struct tty_struct *tty =
        container_of(work, struct tty_struct, hangup_work);

#if 0
    __tty_hangup(tty, 0);
#endif
    panic("%s: END!\n", __func__);
}

static void do_SAK_work(struct work_struct *work)
{
    struct tty_struct *tty =
        container_of(work, struct tty_struct, SAK_work);
#if 0
    __do_SAK(tty);
#endif
    panic("%s: END!\n", __func__);
}

/**
 * alloc_tty_struct - allocate a new tty
 * @driver: driver which will handle the returned tty
 * @idx: minor of the tty
 *
 * This subroutine allocates and initializes a tty structure.
 *
 * Locking: none - @tty in question is not exposed at this point
 */
struct tty_struct *alloc_tty_struct(struct tty_driver *driver, int idx)
{
    struct tty_struct *tty;

    tty = kzalloc(sizeof(*tty), GFP_KERNEL_ACCOUNT);
    if (!tty)
        return NULL;

    kref_init(&tty->kref);
    tty->magic = TTY_MAGIC;
    if (tty_ldisc_init(tty)) {
        kfree(tty);
        return NULL;
    }
    tty->ctrl.session = NULL;
    tty->ctrl.pgrp = NULL;
    mutex_init(&tty->legacy_mutex);
    mutex_init(&tty->throttle_mutex);
    init_rwsem(&tty->termios_rwsem);
    mutex_init(&tty->winsize_mutex);
    init_ldsem(&tty->ldisc_sem);
    init_waitqueue_head(&tty->write_wait);
    init_waitqueue_head(&tty->read_wait);
    INIT_WORK(&tty->hangup_work, do_tty_hangup);
    mutex_init(&tty->atomic_write_lock);
    spin_lock_init(&tty->ctrl.lock);
    spin_lock_init(&tty->flow.lock);
    spin_lock_init(&tty->files_lock);
    INIT_LIST_HEAD(&tty->tty_files);
    INIT_WORK(&tty->SAK_work, do_SAK_work);

    tty->driver = driver;
    tty->ops = driver->ops;
    tty->index = idx;
    tty_line_name(driver, idx, tty->name);
    tty->dev = tty_get_device(tty);

    return tty;
}

/**
 * tty_init_termios -  helper for termios setup
 * @tty: the tty to set up
 *
 * Initialise the termios structure for this tty. This runs under the
 * %tty_mutex currently so we can be relaxed about ordering.
 */
void tty_init_termios(struct tty_struct *tty)
{
    struct ktermios *tp;
    int idx = tty->index;

    if (tty->driver->flags & TTY_DRIVER_RESET_TERMIOS)
        tty->termios = tty->driver->init_termios;
    else {
        /* Check for lazy saved data */
        tp = tty->driver->termios[idx];
        if (tp != NULL) {
            tty->termios = *tp;
            tty->termios.c_line  = tty->driver->init_termios.c_line;
        } else
            tty->termios = tty->driver->init_termios;
    }
    /* Compatibility until drivers always set this */
    tty->termios.c_ispeed = tty_termios_input_baud_rate(&tty->termios);
    tty->termios.c_ospeed = tty_termios_baud_rate(&tty->termios);
}
EXPORT_SYMBOL_GPL(tty_init_termios);

/**
 * tty_standard_install - usual tty->ops->install
 * @driver: the driver for the tty
 * @tty: the tty
 *
 * If the @driver overrides @tty->ops->install, it still can call this function
 * to perform the standard install operations.
 */
int tty_standard_install(struct tty_driver *driver,
                         struct tty_struct *tty)
{
    tty_init_termios(tty);
    tty_driver_kref_get(driver);
    tty->count++;
    driver->ttys[tty->index] = tty;
    return 0;
}
EXPORT_SYMBOL_GPL(tty_standard_install);

/**
 * tty_driver_install_tty() - install a tty entry in the driver
 * @driver: the driver for the tty
 * @tty: the tty
 *
 * Install a tty object into the driver tables. The @tty->index field will be
 * set by the time this is called. This method is responsible for ensuring any
 * need additional structures are allocated and configured.
 *
 * Locking: tty_mutex for now
 */
static int tty_driver_install_tty(struct tty_driver *driver,
                        struct tty_struct *tty)
{
    return driver->ops->install ? driver->ops->install(driver, tty) :
        tty_standard_install(driver, tty);
}

/**
 * tty_init_dev     -   initialise a tty device
 * @driver: tty driver we are opening a device on
 * @idx: device index
 *
 * Prepare a tty device. This may not be a "new" clean device but could also be
 * an active device. The pty drivers require special handling because of this.
 *
 * Locking:
 *  The function is called under the tty_mutex, which protects us from the
 *  tty struct or driver itself going away.
 *
 * On exit the tty device has the line discipline attached and a reference
 * count of 1. If a pair was created for pty/tty use and the other was a pty
 * master then it too has a reference count of 1.
 *
 * WSH 06/09/97: Rewritten to remove races and properly clean up after a failed
 * open. The new code protects the open with a mutex, so it's really quite
 * straightforward. The mutex locking can probably be relaxed for the (most
 * common) case of reopening a tty.
 *
 * Return: new tty structure
 */
struct tty_struct *tty_init_dev(struct tty_driver *driver, int idx)
{
    struct tty_struct *tty;
    int retval;

    /*
     * First time open is complex, especially for PTY devices.
     * This code guarantees that either everything succeeds and the
     * TTY is ready for operation, or else the table slots are vacated
     * and the allocated memory released.  (Except that the termios
     * may be retained.)
     */

    if (!try_module_get(driver->owner))
        return ERR_PTR(-ENODEV);

    tty = alloc_tty_struct(driver, idx);
    if (!tty) {
        retval = -ENOMEM;
        goto err_module_put;
    }

    tty_lock(tty);
    retval = tty_driver_install_tty(driver, tty);
    if (retval < 0)
        goto err_free_tty;

    if (!tty->port)
        tty->port = driver->ports[idx];

    if (WARN_RATELIMIT(!tty->port,
                       "%s: %s driver does not set tty->port. "
                       "This would crash the kernel. Fix the driver!\n",
                       __func__, tty->driver->name)) {
        retval = -EINVAL;
        goto err_release_lock;
    }

    retval = tty_ldisc_lock(tty, 5 * HZ);
    if (retval)
        goto err_release_lock;
    tty->port->itty = tty;

    /*
     * Structures all installed ... call the ldisc open routines.
     * If we fail here just call release_tty to clean up.  No need
     * to decrement the use counts, as release_tty doesn't care.
     */
    retval = tty_ldisc_setup(tty, tty->link);
    if (retval)
        goto err_release_tty;
    tty_ldisc_unlock(tty);
    /* Return the tty locked
       so that it cannot vanish under the caller */
    return tty;

err_free_tty:
    tty_unlock(tty);
    free_tty_struct(tty);
err_module_put:
    module_put(driver->owner);
    return ERR_PTR(retval);

    /* call the tty release_tty routine to clean out this slot */
err_release_tty:
    tty_ldisc_unlock(tty);
    tty_info_ratelimited(tty,
                         "ldisc open failed (%d), clearing slot %d\n",
                         retval, idx);
err_release_lock:
    tty_unlock(tty);
    release_tty(tty, idx);
    return ERR_PTR(retval);
}

/**
 * tty_open_by_driver   -   open a tty device
 * @device: dev_t of device to open
 * @filp: file pointer to tty
 *
 * Performs the driver lookup, checks for a reopen, or otherwise performs the
 * first-time tty initialization.
 *
 *
 * Claims the global tty_mutex to serialize:
 *  * concurrent first-time tty initialization
 *  * concurrent tty driver removal w/ lookup
 *  * concurrent tty removal from driver table
 *
 * Return: the locked initialized or re-opened &tty_struct
 */
static struct tty_struct *
tty_open_by_driver(dev_t device, struct file *filp)
{
    struct tty_struct *tty;
    struct tty_driver *driver = NULL;
    int index = -1;
    int retval;

    mutex_lock(&tty_mutex);
    driver = tty_lookup_driver(device, filp, &index);
    if (IS_ERR(driver)) {
        mutex_unlock(&tty_mutex);
        return ERR_CAST(driver);
    }

    /* check whether we're reopening an existing tty */
    tty = tty_driver_lookup_tty(driver, filp, index);
    if (IS_ERR(tty)) {
        mutex_unlock(&tty_mutex);
        goto out;
    }

    if (tty) {
        panic("%s: tty!\n", __func__);
    } else { /* Returns with the tty_lock held for now */
        tty = tty_init_dev(driver, index);
        mutex_unlock(&tty_mutex);
    }

 out:
    tty_driver_kref_put(driver);
    return tty;
}

/**
 * tty_free_file - free file->private_data
 * @file: to free private_data of
 *
 * This shall be used only for fail path handling when tty_add_file was not
 * called yet.
 */
void tty_free_file(struct file *file)
{
    struct tty_file_private *priv = file->private_data;

    file->private_data = NULL;
    kfree(priv);
}

/* Associate a new file with the tty structure */
void tty_add_file(struct tty_struct *tty, struct file *file)
{
    struct tty_file_private *priv = file->private_data;

    priv->tty = tty;
    priv->file = file;

    spin_lock(&tty->files_lock);
    list_add(&priv->list, &tty->tty_files);
    spin_unlock(&tty->files_lock);
}

/**
 * tty_release      -   vfs callback for close
 * @inode: inode of tty
 * @filp: file pointer for handle to tty
 *
 * Called the last time each file handle is closed that references this tty.
 * There may however be several such references.
 *
 * Locking:
 *  Takes BKL. See tty_release_dev().
 *
 * Even releasing the tty structures is a tricky business. We have to be very
 * careful that the structures are all released at the same time, as interrupts
 * might otherwise get the wrong pointers.
 *
 * WSH 09/09/97: rewritten to avoid some nasty race conditions that could
 * lead to double frees or releasing memory still in use.
 */
int tty_release(struct inode *inode, struct file *filp)
{
    panic("%s: END!\n", __func__);
}

#if 0
static const struct file_operations hung_up_tty_fops = {
    .llseek     = no_llseek,
    .read_iter  = hung_up_tty_read,
    .write_iter = hung_up_tty_write,
    .poll       = hung_up_tty_poll,
    .unlocked_ioctl = hung_up_tty_ioctl,
    .compat_ioctl   = hung_up_tty_compat_ioctl,
    .release    = tty_release,
    .fasync     = hung_up_tty_fasync,
};

/**
 * tty_hung_up_p    -   was tty hung up
 * @filp: file pointer of tty
 *
 * Return: true if the tty has been subject to a vhangup or a carrier loss
 */
int tty_hung_up_p(struct file *filp)
{
    return (filp && filp->f_op == &hung_up_tty_fops);
}
EXPORT_SYMBOL(tty_hung_up_p);
#endif

/**
 * tty_open -   open a tty device
 * @inode: inode of device file
 * @filp: file pointer to tty
 *
 * tty_open() and tty_release() keep up the tty count that contains the number
 * of opens done on a tty. We cannot use the inode-count, as different inodes
 * might point to the same tty.
 *
 * Open-counting is needed for pty masters, as well as for keeping track of
 * serial lines: DTR is dropped when the last close happens.
 * (This is not done solely through tty->count, now.  - Ted 1/27/92)
 *
 * The termios state of a pty is reset on the first open so that settings don't
 * persist across reuse.
 *
 * Locking:
 *  * %tty_mutex protects tty, tty_lookup_driver() and tty_init_dev().
 *  * @tty->count should protect the rest.
 *  * ->siglock protects ->signal/->sighand
 *
 * Note: the tty_unlock/lock cases without a ref are only safe due to %tty_mutex
 */
static int tty_open(struct inode *inode, struct file *filp)
{
    struct tty_struct *tty;
    int noctty, retval;
    dev_t device = inode->i_rdev;
    unsigned saved_flags = filp->f_flags;

    nonseekable_open(inode, filp);

 retry_open:
    retval = tty_alloc_file(filp);
    if (retval)
        return -ENOMEM;

    tty = tty_open_current_tty(device, filp);
    if (!tty)
        tty = tty_open_by_driver(device, filp);

    if (IS_ERR(tty)) {
        tty_free_file(filp);
        retval = PTR_ERR(tty);
        if (retval != -EAGAIN || signal_pending(current))
            return retval;
        schedule();
        goto retry_open;
    }

    tty_add_file(tty, filp);

    //check_tty_count(tty, __func__);

    if (tty->ops->open)
        retval = tty->ops->open(tty, filp);
    else
        retval = -ENODEV;
    filp->f_flags = saved_flags;

    if (retval) {
        tty_unlock(tty); /* need to call tty_release without BTM */
        tty_release(inode, filp);
        if (retval != -ERESTARTSYS)
            return retval;

        if (signal_pending(current))
            return retval;

        schedule();
#if 0
        /*
         * Need to reset f_op in case a hangup happened.
         */
        if (tty_hung_up_p(filp))
            filp->f_op = &tty_fops;
#endif
        goto retry_open;
    }
    clear_bit(TTY_HUPPED, &tty->flags);

    noctty = (filp->f_flags & O_NOCTTY) || (device == MKDEV(TTY_MAJOR, 0)) ||
        device == MKDEV(TTYAUX_MAJOR, 1) ||
        (tty->driver->type == TTY_DRIVER_TYPE_PTY &&
         tty->driver->subtype == PTY_TYPE_MASTER);
#if 0
    if (!noctty)
        tty_open_proc_set_tty(filp, tty);
#endif
    tty_unlock(tty);
    return 0;
}

static int tty_fasync(int fd, struct file *filp, int on)
{
    panic("%s: END!\n", __func__);
}

static void tty_show_fdinfo(struct seq_file *m, struct file *file)
{
    panic("%s: END!\n", __func__);
}

static const struct file_operations tty_fops = {
    .llseek     = no_llseek,
    .read_iter  = tty_read,
    .write_iter = tty_write,
    .splice_read    = generic_file_splice_read,
    .splice_write   = iter_file_splice_write,
    .poll       = tty_poll,
    .unlocked_ioctl = tty_ioctl,
    .compat_ioctl   = tty_compat_ioctl,
    .open       = tty_open,
    .release    = tty_release,
    .fasync     = tty_fasync,
    .show_fdinfo    = tty_show_fdinfo,
};

static const struct file_operations console_fops = {
    .llseek     = no_llseek,
    .read_iter  = tty_read,
    .write_iter = redirected_tty_write,
    .splice_read    = generic_file_splice_read,
    .splice_write   = iter_file_splice_write,
    .poll       = tty_poll,
    .unlocked_ioctl = tty_ioctl,
    .compat_ioctl   = tty_compat_ioctl,
    .open       = tty_open,
    .release    = tty_release,
    .fasync     = tty_fasync,
};

static int tty_cdev_add(struct tty_driver *driver, dev_t dev,
                        unsigned int index, unsigned int count)
{
    int err;

    /* init here, since reused cdevs cause crashes */
    driver->cdevs[index] = cdev_alloc();
    if (!driver->cdevs[index])
        return -ENOMEM;
    driver->cdevs[index]->ops = &tty_fops;
    driver->cdevs[index]->owner = driver->owner;
    err = cdev_add(driver->cdevs[index], dev, count);
    if (err)
        kobject_put(&driver->cdevs[index]->kobj);
    return err;
}

/**
 * tty_register_device_attr - register a tty device
 * @driver: the tty driver that describes the tty device
 * @index: the index in the tty driver for this tty device
 * @device: a struct device that is associated with this tty device.
 *  This field is optional, if there is no known struct device
 *  for this tty device it can be set to %NULL safely.
 * @drvdata: Driver data to be set to device.
 * @attr_grp: Attribute group to be set on device.
 *
 * This call is required to be made to register an individual tty device if the
 * tty driver's flags have the %TTY_DRIVER_DYNAMIC_DEV bit set. If that bit is
 * not set, this function should not be called by a tty driver.
 *
 * Locking: ??
 *
 * Return: A pointer to the struct device for this tty device (or
 * ERR_PTR(-EFOO) on error).
 */
struct device *
tty_register_device_attr(struct tty_driver *driver,
                         unsigned index,
                         struct device *device,
                         void *drvdata,
                         const struct attribute_group **attr_grp)
{
    char name[64];
    dev_t devt = MKDEV(driver->major, driver->minor_start) + index;
    struct ktermios *tp;
    struct device *dev;
    int retval;

    if (index >= driver->num) {
        pr_err("%s: Attempt to register invalid tty line number (%d)\n",
               driver->name, index);
        return ERR_PTR(-EINVAL);
    }

    if (driver->type == TTY_DRIVER_TYPE_PTY)
        pty_line_name(driver, index, name);
    else
        tty_line_name(driver, index, name);

    dev = kzalloc(sizeof(*dev), GFP_KERNEL);
    if (!dev)
        return ERR_PTR(-ENOMEM);

    dev->devt = devt;
    dev->class = tty_class;
    dev->parent = device;
    dev->release = tty_device_create_release;
    dev_set_name(dev, "%s", name);
    //dev->groups = attr_grp;
    dev_set_drvdata(dev, drvdata);

    dev_set_uevent_suppress(dev, 1);

    retval = device_register(dev);
    if (retval)
        goto err_put;

    if (!(driver->flags & TTY_DRIVER_DYNAMIC_ALLOC)) {
        /*
         * Free any saved termios data so that the termios state is
         * reset when reusing a minor number.
         */
        tp = driver->termios[index];
        if (tp) {
            driver->termios[index] = NULL;
            kfree(tp);
        }

        retval = tty_cdev_add(driver, devt, index, 1);
        if (retval)
            goto err_del;
    }

    dev_set_uevent_suppress(dev, 0);
    //kobject_uevent(&dev->kobj, KOBJ_ADD);

    return dev;

 err_del:
    device_del(dev);
 err_put:
    put_device(dev);

    return ERR_PTR(retval);
}
/**
 * tty_register_device - register a tty device
 * @driver: the tty driver that describes the tty device
 * @index: the index in the tty driver for this tty device
 * @device: a struct device that is associated with this tty device.
 *  This field is optional, if there is no known struct device
 *  for this tty device it can be set to NULL safely.
 *
 * This call is required to be made to register an individual tty device
 * if the tty driver's flags have the %TTY_DRIVER_DYNAMIC_DEV bit set.  If
 * that bit is not set, this function should not be called by a tty
 * driver.
 *
 * Locking: ??
 *
 * Return: A pointer to the struct device for this tty device (or
 * ERR_PTR(-EFOO) on error).
 */
struct device *
tty_register_device(struct tty_driver *driver, unsigned index,
                    struct device *device)
{
    return tty_register_device_attr(driver, index, device, NULL, NULL);
}
EXPORT_SYMBOL(tty_register_device);

/**
 * tty_register_driver -- register a tty driver
 * @driver: driver to register
 *
 * Called by a tty driver to register itself.
 */
int tty_register_driver(struct tty_driver *driver)
{
    int error;
    int i;
    dev_t dev;
    struct device *d;

    if (!driver->major) {
#if 0
        error = alloc_chrdev_region(&dev, driver->minor_start,
                                    driver->num, driver->name);
        if (!error) {
            driver->major = MAJOR(dev);
            driver->minor_start = MINOR(dev);
        }
#endif
        panic("%s: 1!\n", __func__);
    } else {
        dev = MKDEV(driver->major, driver->minor_start);
        error = register_chrdev_region(dev, driver->num, driver->name);
    }
    if (error < 0)
        goto err;

    if (driver->flags & TTY_DRIVER_DYNAMIC_ALLOC) {
#if 0
        error = tty_cdev_add(driver, dev, 0, driver->num);
        if (error)
            goto err_unreg_char;
#endif
        panic("%s: 3!\n", __func__);
    }

    mutex_lock(&tty_mutex);
    list_add(&driver->tty_drivers, &tty_drivers);
    mutex_unlock(&tty_mutex);

    if (!(driver->flags & TTY_DRIVER_DYNAMIC_DEV)) {
        for (i = 0; i < driver->num; i++) {
            d = tty_register_device(driver, i, NULL);
            if (IS_ERR(d)) {
                error = PTR_ERR(d);
                goto err_unreg_devs;
            }
        }
    }
    //proc_tty_register_driver(driver);
    driver->flags |= TTY_DRIVER_INSTALLED;
    return 0;

 err_unreg_devs:
    for (i--; i >= 0; i--)
        tty_unregister_device(driver, i);

    mutex_lock(&tty_mutex);
    list_del(&driver->tty_drivers);
    mutex_unlock(&tty_mutex);

 err_unreg_char:
    unregister_chrdev_region(dev, driver->num);
 err:
    return error;
}
EXPORT_SYMBOL(tty_register_driver);

static char *tty_devnode(struct device *dev, umode_t *mode)
{
    if (!mode)
        return NULL;
    if (dev->devt == MKDEV(TTYAUX_MAJOR, 0) ||
        dev->devt == MKDEV(TTYAUX_MAJOR, 2))
        *mode = 0666;
    return NULL;
}

/**
 * tty_vhangup      -   process vhangup
 * @tty: tty to hangup
 *
 * The user has asked via system call for the terminal to be hung up. We do
 * this synchronously so that when the syscall returns the process is complete.
 * That guarantee is necessary for security reasons.
 */
void tty_vhangup(struct tty_struct *tty)
{
#if 0
    tty_debug_hangup(tty, "vhangup\n");
    __tty_hangup(tty, 0);
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(tty_vhangup);

static void queue_release_one_tty(struct kref *kref)
{
#if 0
    struct tty_struct *tty = container_of(kref, struct tty_struct, kref);

    /* The hangup queue is now free so we can reuse it rather than
     *  waste a chunk of memory for each port.
     */
    INIT_WORK(&tty->hangup_work, release_one_tty);
    schedule_work(&tty->hangup_work);
#endif
    panic("%s: END!\n", __func__);
}

/**
 * tty_kref_put     -   release a tty kref
 * @tty: tty device
 *
 * Release a reference to the @tty device and if need be let the kref layer
 * destruct the object for us.
 */
void tty_kref_put(struct tty_struct *tty)
{
    if (tty)
        kref_put(&tty->kref, queue_release_one_tty);
}
EXPORT_SYMBOL(tty_kref_put);

static int __init tty_class_init(void)
{
    tty_class = class_create(THIS_MODULE, "tty");
    if (IS_ERR(tty_class))
        return PTR_ERR(tty_class);
    tty_class->devnode = tty_devnode;
    return 0;
}
postcore_initcall(tty_class_init);

/**
 * tty_wakeup   -   request more data
 * @tty: terminal
 *
 * Internal and external helper for wakeups of tty. This function informs the
 * line discipline if present that the driver is ready to receive more output
 * data.
 */
void tty_wakeup(struct tty_struct *tty)
{
    struct tty_ldisc *ld;

    if (test_bit(TTY_DO_WRITE_WAKEUP, &tty->flags)) {
        ld = tty_ldisc_ref(tty);
        if (ld) {
            if (ld->ops->write_wakeup)
                ld->ops->write_wakeup(tty);
            tty_ldisc_deref(ld);
        }
    }
    wake_up_interruptible_poll(&tty->write_wait, EPOLLOUT);
}
EXPORT_SYMBOL_GPL(tty_wakeup);

void __start_tty(struct tty_struct *tty)
{
    if (!tty->flow.stopped || tty->flow.tco_stopped)
        return;
    tty->flow.stopped = false;
    if (tty->ops->start)
        tty->ops->start(tty);
    tty_wakeup(tty);
}

/**
 * start_tty    -   propagate flow control
 * @tty: tty to start
 *
 * Start a tty that has been stopped if at all possible. If @tty was previously
 * stopped and is now being started, the &tty_driver->start() method is invoked
 * and the line discipline woken.
 *
 * Locking:
 *  flow.lock
 */
void start_tty(struct tty_struct *tty)
{
    unsigned long flags;

    spin_lock_irqsave(&tty->flow.lock, flags);
    __start_tty(tty);
    spin_unlock_irqrestore(&tty->flow.lock, flags);
}
EXPORT_SYMBOL(start_tty);

static struct device *consdev;

/*
 * Ok, now we can initialize the rest of the tty devices and can count
 * on memory allocations, interrupts etc..
 */
int __init tty_init(void)
{
#if 0
    tty_sysctl_init();
#endif
    cdev_init(&tty_cdev, &tty_fops);
    if (cdev_add(&tty_cdev, MKDEV(TTYAUX_MAJOR, 0), 1) ||
        register_chrdev_region(MKDEV(TTYAUX_MAJOR, 0), 1, "/dev/tty") < 0)
        panic("Couldn't register /dev/tty driver\n");
    device_create(tty_class, NULL, MKDEV(TTYAUX_MAJOR, 0), NULL, "tty");

    cdev_init(&console_cdev, &console_fops);
    if (cdev_add(&console_cdev, MKDEV(TTYAUX_MAJOR, 1), 1) ||
        register_chrdev_region(MKDEV(TTYAUX_MAJOR, 1), 1, "/dev/console") < 0)
        panic("Couldn't register /dev/console driver\n");
#if 0
    consdev = device_create_with_groups(tty_class, NULL,
                                        MKDEV(TTYAUX_MAJOR, 1), NULL,
                                        cons_dev_groups, "console");
#else
    consdev = device_create_with_groups(tty_class, NULL,
                                        MKDEV(TTYAUX_MAJOR, 1), NULL,
                                        NULL, "console");
#endif
    if (IS_ERR(consdev))
        consdev = NULL;

#if 0
    vty_init(&console_fops);
#endif
    return 0;
}

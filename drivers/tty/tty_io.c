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
//#include <linux/vt_kern.h>
//#include <linux/selection.h>

#include <linux/kmod.h>
#include <linux/nsproxy.h>
#include "tty.h"

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
    panic("%s: END!\n", __func__);
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

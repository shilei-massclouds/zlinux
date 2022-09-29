// SPDX-License-Identifier: GPL-2.0
/*
 * Tty port functions
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
//#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/wait.h>
#include <linux/bitops.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/serdev.h>
#include "tty.h"

static int tty_port_default_receive_buf(struct tty_port *port,
                                        const unsigned char *p,
                                        const unsigned char *f,
                                        size_t count)
{
    panic("%s: END!\n", __func__);
}

static void tty_port_default_wakeup(struct tty_port *port)
{
    panic("%s: END!\n", __func__);
}

const struct tty_port_client_operations tty_port_default_client_ops = {
    .receive_buf = tty_port_default_receive_buf,
    .write_wakeup = tty_port_default_wakeup,
};
EXPORT_SYMBOL_GPL(tty_port_default_client_ops);

/**
 * tty_port_destroy -- destroy inited port
 * @port: tty port to be destroyed
 *
 * When a port was initialized using tty_port_init(), one has to destroy the
 * port by this function. Either indirectly by using &tty_port refcounting
 * (tty_port_put()) or directly if refcounting is not used.
 */
void tty_port_destroy(struct tty_port *port)
{
#if 0
    tty_buffer_cancel_work(port);
    tty_buffer_free_all(port);
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(tty_port_destroy);

/**
 * tty_port_link_device - link tty and tty_port
 * @port: tty_port of the device
 * @driver: tty_driver for this device
 * @index: index of the tty
 *
 * Provide the tty layer with a link from a tty (specified by @index) to a
 * tty_port (@port). Use this only if neither tty_port_register_device() nor
 * tty_port_install() is used in the driver. If used, this has to be called
 * before tty_register_driver().
 */
void tty_port_link_device(struct tty_port *port,
        struct tty_driver *driver, unsigned index)
{
    if (WARN_ON(index >= driver->num))
        return;
    driver->ports[index] = port;
}
EXPORT_SYMBOL_GPL(tty_port_link_device);

/**
 * tty_port_register_device_attr_serdev - register tty or serdev device
 * @port: tty_port of the device
 * @driver: tty_driver for this device
 * @index: index of the tty
 * @device: parent if exists, otherwise NULL
 * @drvdata: driver data for the device
 * @attr_grp: attribute group for the device
 *
 * Register a serdev or tty device depending on if the parent device has any
 * defined serdev clients or not.
 */
struct device *
tty_port_register_device_attr_serdev(struct tty_port *port,
                                     struct tty_driver *driver,
                                     unsigned index,
                                     struct device *device,
                                     void *drvdata,
                                     const struct attribute_group **attr_grp)
{
    struct device *dev;

    tty_port_link_device(port, driver, index);

#if 0
    dev = serdev_tty_port_register(port, device, driver, index);
    if (PTR_ERR(dev) != -ENODEV) {
        /* Skip creating cdev if we registered a serdev device */
        return dev;
    }
#endif

    return tty_register_device_attr(driver, index, device, drvdata,
                                    attr_grp);
}
EXPORT_SYMBOL_GPL(tty_port_register_device_attr_serdev);

/**
 * tty_port_unregister_device - deregister a tty or serdev device
 * @port: tty_port of the device
 * @driver: tty_driver for this device
 * @index: index of the tty
 *
 * If a tty or serdev device is registered with a call to
 * tty_port_register_device_serdev() then this function must be called when
 * the device is gone.
 */
void tty_port_unregister_device(struct tty_port *port,
                                struct tty_driver *driver,
                                unsigned index)
{
    int ret;

    ret = serdev_tty_port_unregister(port);
    if (ret == 0)
        return;

    tty_unregister_device(driver, index);
}
EXPORT_SYMBOL_GPL(tty_port_unregister_device);

/**
 * tty_port_tty_get -   get a tty reference
 * @port: tty port
 *
 * Return a refcount protected tty instance or %NULL if the port is not
 * associated with a tty (eg due to close or hangup).
 */
struct tty_struct *tty_port_tty_get(struct tty_port *port)
{
    unsigned long flags;
    struct tty_struct *tty;

    spin_lock_irqsave(&port->lock, flags);
    tty = tty_kref_get(port->tty);
    spin_unlock_irqrestore(&port->lock, flags);
    return tty;
}
EXPORT_SYMBOL(tty_port_tty_get);

/**
 * tty_port_tty_set -   set the tty of a port
 * @port: tty port
 * @tty: the tty
 *
 * Associate the port and tty pair. Manages any internal refcounts. Pass %NULL
 * to deassociate a port.
 */
void tty_port_tty_set(struct tty_port *port, struct tty_struct *tty)
{
    unsigned long flags;

    spin_lock_irqsave(&port->lock, flags);
    tty_kref_put(port->tty);
    port->tty = tty_kref_get(tty);
    spin_unlock_irqrestore(&port->lock, flags);
}
EXPORT_SYMBOL(tty_port_tty_set);

/**
 * tty_port_raise_dtr_rts   -   Raise DTR/RTS
 * @port: tty port
 *
 * Wrapper for the DTR/RTS raise logic. For the moment this is used to hide
 * some internal details. This will eventually become entirely internal to the
 * tty port.
 */
void tty_port_raise_dtr_rts(struct tty_port *port)
{
    if (port->ops->dtr_rts)
        port->ops->dtr_rts(port, 1);
}
EXPORT_SYMBOL(tty_port_raise_dtr_rts);

/**
 * tty_port_block_til_ready -   Waiting logic for tty open
 * @port: the tty port being opened
 * @tty: the tty device being bound
 * @filp: the file pointer of the opener or %NULL
 *
 * Implement the core POSIX/SuS tty behaviour when opening a tty device.
 * Handles:
 *
 *  - hangup (both before and during)
 *  - non blocking open
 *  - rts/dtr/dcd
 *  - signals
 *  - port flags and counts
 *
 * The passed @port must implement the @port->ops->carrier_raised method if it
 * can do carrier detect and the @port->ops->dtr_rts method if it supports
 * software management of these lines. Note that the dtr/rts raise is done each
 * iteration as a hangup may have previously dropped them while we wait.
 *
 * Caller holds tty lock.
 *
 * Note: May drop and reacquire tty lock when blocking, so @tty and @port may
 * have changed state (eg., may have been hung up).
 */
int tty_port_block_til_ready(struct tty_port *port,
                             struct tty_struct *tty,
                             struct file *filp)
{
    int do_clocal = 0, retval;
    unsigned long flags;
    DEFINE_WAIT(wait);

    /* if non-blocking mode is set we can pass directly to open unless
     * the port has just hung up or is in another error state.
     */
    if (tty_io_error(tty)) {
        tty_port_set_active(port, 1);
        return 0;
    }
    if (filp == NULL || (filp->f_flags & O_NONBLOCK)) {
        /* Indicate we are open */
        if (C_BAUD(tty))
            tty_port_raise_dtr_rts(port);
        tty_port_set_active(port, 1);
        return 0;
    }

    panic("%s: END!\n", __func__);
}

/**
 * tty_port_open - generic tty->ops->open handler
 * @port: tty_port of the device
 * @tty: tty to be opened
 * @filp: passed file pointer
 *
 * It is a generic helper to be used in driver's @tty->ops->open. It activates
 * the devices using @port->ops->activate if not active already. And waits for
 * the device to be ready using tty_port_block_til_ready() (e.g.  raises
 * DTR/CTS and waits for carrier).
 *
 * Note that @port->ops->shutdown is not called when @port->ops->activate
 * returns an error (on the contrary, @tty->ops->close is).
 *
 * Locking: Caller holds tty lock.
 *
 * Note: may drop and reacquire tty lock (in tty_port_block_til_ready()) so
 * @tty and @port may have changed state (eg., may be hung up now).
 */
int tty_port_open(struct tty_port *port, struct tty_struct *tty,
                            struct file *filp)
{
    spin_lock_irq(&port->lock);
    ++port->count;
    spin_unlock_irq(&port->lock);
    tty_port_tty_set(port, tty);

    /*
     * Do the device-specific open only if the hardware isn't
     * already initialized. Serialize open and shutdown using the
     * port mutex.
     */

    mutex_lock(&port->mutex);

    if (!tty_port_initialized(port)) {
        clear_bit(TTY_IO_ERROR, &tty->flags);
        if (port->ops->activate) {
            int retval = port->ops->activate(port, tty);

            if (retval) {
                mutex_unlock(&port->mutex);
                return retval;
            }
        }
        tty_port_set_initialized(port, 1);
    }
    mutex_unlock(&port->mutex);
    return tty_port_block_til_ready(port, tty, filp);
}

/**
 * tty_port_init -- initialize tty_port
 * @port: tty_port to initialize
 *
 * Initializes the state of struct tty_port. When a port was initialized using
 * this function, one has to destroy the port by tty_port_destroy(). Either
 * indirectly by using &tty_port refcounting (tty_port_put()) or directly if
 * refcounting is not used.
 */
void tty_port_init(struct tty_port *port)
{
    memset(port, 0, sizeof(*port));
    tty_buffer_init(port);
    init_waitqueue_head(&port->open_wait);
    init_waitqueue_head(&port->delta_msr_wait);
    mutex_init(&port->mutex);
    mutex_init(&port->buf_mutex);
    spin_lock_init(&port->lock);
    port->close_delay = (50 * HZ) / 100;
    port->closing_wait = (3000 * HZ) / 100;
    port->client_ops = &tty_port_default_client_ops;
    kref_init(&port->kref);
}
EXPORT_SYMBOL(tty_port_init);

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
//#include <linux/serdev.h>
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

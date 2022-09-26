// SPDX-License-Identifier: GPL-2.0+
/*
 *  Driver core for serial ports
 *
 *  Based on drivers/char/serial.c, by Linus Torvalds, Theodore Ts'o.
 *
 *  Copyright 1999 ARM Limited
 *  Copyright (C) 2000-2001 Deep Blue Solutions Ltd.
 */
#include <linux/module.h>
/*
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
*/
#include <linux/init.h>
#include <linux/console.h>
#include <linux/of.h>
#if 0
#include <linux/gpio/consumer.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#endif
#include <linux/device.h>
#include <linux/serial.h> /* for serial_state and serial_icounter_struct */
#include <linux/serial_core.h>
/*
#include <linux/sysrq.h>
#include <linux/delay.h>
#include <linux/mutex.h>
#include <linux/security.h>

#include <linux/irq.h>
*/
#include <linux/uaccess.h>

/*
 * This is used to lock changes in serial line configuration.
 */
static DEFINE_MUTEX(port_mutex);

/**
 *  uart_console_write - write a console message to a serial port
 *  @port: the port to write the message
 *  @s: array of characters
 *  @count: number of characters in string to write
 *  @putchar: function to write character to port
 */
void uart_console_write(struct uart_port *port,
                        const char *s, unsigned int count,
                        void (*putchar)(struct uart_port *, int))
{
    unsigned int i;

    for (i = 0; i < count; i++, s++) {
        if (*s == '\n')
            putchar(port, '\r');
        putchar(port, *s);
    }
}
EXPORT_SYMBOL_GPL(uart_console_write);

/*
 *  Are the two ports equivalent?
 */
bool uart_match_port(const struct uart_port *port1,
                     const struct uart_port *port2)
{
    if (port1->iotype != port2->iotype)
        return false;

    switch (port1->iotype) {
    case UPIO_PORT:
        return port1->iobase == port2->iobase;
    case UPIO_HUB6:
        return port1->iobase == port2->iobase &&
               port1->hub6   == port2->hub6;
    case UPIO_MEM:
    case UPIO_MEM16:
    case UPIO_MEM32:
    case UPIO_MEM32BE:
    case UPIO_AU:
    case UPIO_TSI:
        return port1->mapbase == port2->mapbase;
    }

    return false;
}
EXPORT_SYMBOL(uart_match_port);

static int uart_install(struct tty_driver *driver,
                        struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

/*
 * Calls to uart_open are serialised by the tty_lock in
 *   drivers/tty/tty_io.c:tty_open()
 * Note that if this fails, then uart_close() _will_ be called.
 *
 * In time, we want to scrap the "opening nonpresent ports"
 * behaviour and implement an alternative way for setserial
 * to set base addresses/ports/types.  This will allow us to
 * get rid of a certain amount of extra tests.
 */
static int uart_open(struct tty_struct *tty, struct file *filp)
{
    panic("%s: END!\n", __func__);
}

/*
 * Calls to uart_close() are serialised via the tty_lock in
 *   drivers/tty/tty_io.c:tty_release()
 *   drivers/tty/tty_io.c:do_tty_hangup()
 */
static void uart_close(struct tty_struct *tty, struct file *filp)
{
    panic("%s: END!\n", __func__);
}

static int uart_write(struct tty_struct *tty,
                      const unsigned char *buf, int count)
{
    panic("%s: END!\n", __func__);
}

static int uart_put_char(struct tty_struct *tty, unsigned char c)
{
    panic("%s: END!\n", __func__);
}

static void uart_flush_chars(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

static unsigned int uart_write_room(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

static unsigned int uart_chars_in_buffer(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

static void uart_flush_buffer(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

/*
 * Called via sys_ioctl.  We can use spin_lock_irq() here.
 */
static int
uart_ioctl(struct tty_struct *tty, unsigned int cmd, unsigned long arg)
{
    panic("%s: END!\n", __func__);
}

static void uart_throttle(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

static void uart_unthrottle(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

/*
 * This function is used to send a high-priority XON/XOFF character to
 * the device
 */
static void uart_send_xchar(struct tty_struct *tty, char ch)
{
    panic("%s: END!\n", __func__);
}

static void uart_set_termios(struct tty_struct *tty,
                             struct ktermios *old_termios)
{
    panic("%s: END!\n", __func__);
}

static void uart_set_ldisc(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

static void uart_stop(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

static void uart_start(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

/*
 * Calls to uart_hangup() are serialised by the tty_lock in
 *   drivers/tty/tty_io.c:do_tty_hangup()
 * This runs from a workqueue and can sleep for a _short_ time only.
 */
static void uart_hangup(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

static int uart_break_ctl(struct tty_struct *tty, int break_state)
{
    panic("%s: END!\n", __func__);
}

static void uart_wait_until_sent(struct tty_struct *tty, int timeout)
{
    panic("%s: END!\n", __func__);
}

static int uart_proc_show(struct seq_file *m, void *v)
{
    panic("%s: END!\n", __func__);
}

static int uart_tiocmget(struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

static int
uart_tiocmset(struct tty_struct *tty, unsigned int set,
              unsigned int clear)
{
    panic("%s: END!\n", __func__);
}

static int
uart_set_info_user(struct tty_struct *tty, struct serial_struct *ss)
{
    panic("%s: END!\n", __func__);
}

static int uart_get_info_user(struct tty_struct *tty,
                              struct serial_struct *ss)
{
    panic("%s: END!\n", __func__);
}

/*
 * Get counter of input serial line interrupts (DCD,RI,DSR,CTS)
 * Return: write counters to the user passed counter struct
 * NB: both 1->0 and 0->1 transitions are counted except for
 *     RI where only 0->1 is counted.
 */
static int uart_get_icount(struct tty_struct *tty,
                           struct serial_icounter_struct *icount)
{
    panic("%s: END!\n", __func__);
}

static const struct tty_operations uart_ops = {
    .install    = uart_install,
    .open       = uart_open,
    .close      = uart_close,
    .write      = uart_write,
    .put_char   = uart_put_char,
    .flush_chars    = uart_flush_chars,
    .write_room = uart_write_room,
    .chars_in_buffer= uart_chars_in_buffer,
    .flush_buffer   = uart_flush_buffer,
    .ioctl      = uart_ioctl,
    .throttle   = uart_throttle,
    .unthrottle = uart_unthrottle,
    .send_xchar = uart_send_xchar,
    .set_termios    = uart_set_termios,
    .set_ldisc  = uart_set_ldisc,
    .stop       = uart_stop,
    .start      = uart_start,
    .hangup     = uart_hangup,
    .break_ctl  = uart_break_ctl,
    .wait_until_sent= uart_wait_until_sent,
    .proc_show  = uart_proc_show,
    .tiocmget   = uart_tiocmget,
    .tiocmset   = uart_tiocmset,
    .set_serial = uart_set_info_user,
    .get_serial = uart_get_info_user,
    .get_icount = uart_get_icount,
};

static int uart_carrier_raised(struct tty_port *port)
{
    panic("%s: END!\n", __func__);
}

static void uart_dtr_rts(struct tty_port *port, int raise)
{
    panic("%s: END!\n", __func__);
}

static int uart_port_activate(struct tty_port *port,
                              struct tty_struct *tty)
{
    panic("%s: END!\n", __func__);
}

static void uart_tty_port_shutdown(struct tty_port *port)
{
    panic("%s: END!\n", __func__);
}

static const struct tty_port_operations uart_port_ops = {
    .carrier_raised = uart_carrier_raised,
    .dtr_rts    = uart_dtr_rts,
    .activate   = uart_port_activate,
    .shutdown   = uart_tty_port_shutdown,
};

/**
 *  uart_register_driver - register a driver with the uart core layer
 *  @drv: low level driver structure
 *
 *  Register a uart driver with the core driver.  We in turn register
 *  with the tty layer, and initialise the core driver per-port state.
 *
 *  We have a proc file in /proc/tty/driver which is named after the
 *  normal driver.
 *
 *  drv->port should be NULL, and the per-port structures should be
 *  registered using uart_add_one_port after this call has succeeded.
 */
int uart_register_driver(struct uart_driver *drv)
{
    struct tty_driver *normal;
    int i, retval = -ENOMEM;

    BUG_ON(drv->state);

    /*
     * Maybe we should be using a slab cache for this, especially if
     * we have a large number of ports to handle.
     */
    drv->state = kcalloc(drv->nr, sizeof(struct uart_state), GFP_KERNEL);
    if (!drv->state)
        goto out;

    normal = tty_alloc_driver(drv->nr, TTY_DRIVER_REAL_RAW |
                              TTY_DRIVER_DYNAMIC_DEV);
    if (IS_ERR(normal)) {
        retval = PTR_ERR(normal);
        goto out_kfree;
    }

    drv->tty_driver = normal;

    normal->driver_name = drv->driver_name;
    normal->name        = drv->dev_name;
    normal->major       = drv->major;
    normal->minor_start = drv->minor;
    normal->type        = TTY_DRIVER_TYPE_SERIAL;
    normal->subtype     = SERIAL_TYPE_NORMAL;
    normal->init_termios    = tty_std_termios;
    normal->init_termios.c_cflag = B9600 | CS8 | CREAD | HUPCL | CLOCAL;
    normal->init_termios.c_ispeed =
        normal->init_termios.c_ospeed = 9600;
    normal->driver_state    = drv;
    tty_set_operations(normal, &uart_ops);

    /*
     * Initialise the UART state(s).
     */
    for (i = 0; i < drv->nr; i++) {
        struct uart_state *state = drv->state + i;
        struct tty_port *port = &state->port;

        tty_port_init(port);
        port->ops = &uart_port_ops;
    }

    retval = tty_register_driver(normal);
    if (retval >= 0)
        return retval;

    for (i = 0; i < drv->nr; i++)
        tty_port_destroy(&drv->state[i].port);
    tty_driver_kref_put(normal);

 out_kfree:
    kfree(drv->state);
 out:
    return retval;
}

/**
 *  uart_unregister_driver - remove a driver from the uart core layer
 *  @drv: low level driver structure
 *
 *  Remove all references to a driver from the core driver.  The low
 *  level driver must have removed all its ports via the
 *  uart_remove_one_port() if it registered them with uart_add_one_port().
 *  (ie, drv->port == NULL)
 */
void uart_unregister_driver(struct uart_driver *drv)
{
#if 0
    struct tty_driver *p = drv->tty_driver;
    unsigned int i;

    tty_unregister_driver(p);
    tty_driver_kref_put(p);
    for (i = 0; i < drv->nr; i++)
        tty_port_destroy(&drv->state[i].port);
    kfree(drv->state);
    drv->state = NULL;
    drv->tty_driver = NULL;
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL(uart_unregister_driver);

static inline bool uart_console_enabled(struct uart_port *port)
{
    return uart_console(port) && (port->cons->flags & CON_ENABLED);
}

static void uart_port_spin_lock_init(struct uart_port *port)
{
    spin_lock_init(&port->lock);
}

static void
uart_configure_port(struct uart_driver *drv, struct uart_state *state,
            struct uart_port *port)
{
    unsigned int flags;

    /*
     * If there isn't a port here, don't do anything further.
     */
    if (!port->iobase && !port->mapbase && !port->membase)
        return;

    panic("%s: END!\n", __func__);
}

#if 0
static struct attribute *tty_dev_attrs[] = {
    &dev_attr_uartclk.attr,
    &dev_attr_type.attr,
    &dev_attr_line.attr,
    &dev_attr_port.attr,
    &dev_attr_irq.attr,
    &dev_attr_flags.attr,
    &dev_attr_xmit_fifo_size.attr,
    &dev_attr_close_delay.attr,
    &dev_attr_closing_wait.attr,
    &dev_attr_custom_divisor.attr,
    &dev_attr_io_type.attr,
    &dev_attr_iomem_base.attr,
    &dev_attr_iomem_reg_shift.attr,
    &dev_attr_console.attr,
    NULL
};

static const struct attribute_group tty_dev_attr_group = {
    .attrs = tty_dev_attrs,
};
#endif

/**
 *  uart_add_one_port - attach a driver-defined port structure
 *  @drv: pointer to the uart low level driver structure for this port
 *  @uport: uart port structure to use for this port.
 *
 *  Context: task context, might sleep
 *
 *  This allows the driver to register its own uart_port structure
 *  with the core driver.  The main purpose is to allow the low
 *  level uart drivers to expand uart_port, rather than having yet
 *  more levels of structures.
 */
int uart_add_one_port(struct uart_driver *drv, struct uart_port *uport)
{
    struct uart_state *state;
    struct tty_port *port;
    int ret = 0;
    struct device *tty_dev;
    int num_groups;

    if (uport->line >= drv->nr)
        return -EINVAL;

    state = drv->state + uport->line;
    port = &state->port;

    mutex_lock(&port_mutex);
    mutex_lock(&port->mutex);
    if (state->uart_port) {
        ret = -EINVAL;
        goto out;
    }

    /* Link the port to the driver state table and vice versa */
    atomic_set(&state->refcount, 1);
    init_waitqueue_head(&state->remove_wait);
    state->uart_port = uport;
    uport->state = state;

    state->pm_state = UART_PM_STATE_UNDEFINED;
    uport->cons = drv->cons;
    uport->minor = drv->tty_driver->minor_start + uport->line;
    uport->name = kasprintf(GFP_KERNEL, "%s%d", drv->dev_name,
                drv->tty_driver->name_base + uport->line);
    if (!uport->name) {
        ret = -ENOMEM;
        goto out;
    }

    /*
     * If this port is in use as a console then the spinlock is already
     * initialised.
     */
    if (!uart_console_enabled(uport))
        uart_port_spin_lock_init(uport);

    if (uport->cons && uport->dev)
        of_console_check(uport->dev->of_node, uport->cons->name,
                         uport->line);

    tty_port_link_device(port, drv->tty_driver, uport->line);
    uart_configure_port(drv, state, uport);

    port->console = uart_console(uport);

    num_groups = 2;
    if (uport->attr_group)
        num_groups++;

    uport->tty_groups = kcalloc(num_groups, sizeof(*uport->tty_groups),
                                GFP_KERNEL);
    if (!uport->tty_groups) {
        ret = -ENOMEM;
        goto out;
    }
#if 0
    uport->tty_groups[0] = &tty_dev_attr_group;
    if (uport->attr_group)
        uport->tty_groups[1] = uport->attr_group;
#endif

    /*
     * Register the port whether it's detected or not.  This allows
     * setserial to be used to alter this port's parameters.
     */
    tty_dev =
        tty_port_register_device_attr_serdev(port, drv->tty_driver,
                                             uport->line, uport->dev,
                                             port, uport->tty_groups);
    if (!IS_ERR(tty_dev)) {
#if 0
        device_set_wakeup_capable(tty_dev, 1);
#endif
    } else {
        dev_err(uport->dev, "Cannot register tty device on line %d\n",
                uport->line);
    }

    /*
     * Ensure UPF_DEAD is not set.
     */
    uport->flags &= ~UPF_DEAD;

 out:
    mutex_unlock(&port->mutex);
    mutex_unlock(&port_mutex);

    return ret;
}
EXPORT_SYMBOL(uart_add_one_port);

static inline
struct uart_port *uart_port_check(struct uart_state *state)
{
    return state->uart_port;
}

/**
 *  uart_remove_one_port - detach a driver defined port structure
 *  @drv: pointer to the uart low level driver structure for this port
 *  @uport: uart port structure for this port
 *
 *  Context: task context, might sleep
 *
 *  This unhooks (and hangs up) the specified port structure from the
 *  core driver.  No further calls will be made to the low-level code
 *  for this port.
 */
int uart_remove_one_port(struct uart_driver *drv,
                         struct uart_port *uport)
{
    struct uart_state *state = drv->state + uport->line;
    struct tty_port *port = &state->port;
    struct uart_port *uart_port;
    struct tty_struct *tty;
    int ret = 0;

    mutex_lock(&port_mutex);

    /*
     * Mark the port "dead" - this prevents any opens from
     * succeeding while we shut down the port.
     */
    mutex_lock(&port->mutex);
    uart_port = uart_port_check(state);
    if (uart_port != uport)
        dev_alert(uport->dev, "Removing wrong port: %p != %p\n",
                  uart_port, uport);

    if (!uart_port) {
        mutex_unlock(&port->mutex);
        ret = -EINVAL;
        goto out;
    }
    uport->flags |= UPF_DEAD;
    mutex_unlock(&port->mutex);

    /*
     * Remove the devices from the tty layer
     */
    tty_port_unregister_device(port, drv->tty_driver, uport->line);

    tty = tty_port_tty_get(port);
    if (tty) {
        tty_vhangup(port->tty);
        tty_kref_put(tty);
    }

    /*
     * If the port is used as a console, unregister it
     */
    if (uart_console(uport))
        unregister_console(uport->cons);

    /*
     * Free the port IO and memory resources, if any.
     */
    if (uport->type != PORT_UNKNOWN && uport->ops->release_port)
        uport->ops->release_port(uport);
    kfree(uport->tty_groups);
    kfree(uport->name);

    /*
     * Indicate that there isn't a port here anymore.
     */
    uport->type = PORT_UNKNOWN;

    mutex_lock(&port->mutex);
    WARN_ON(atomic_dec_return(&state->refcount) < 0);
    wait_event(state->remove_wait, !atomic_read(&state->refcount));
    state->uart_port = NULL;
    mutex_unlock(&port->mutex);
 out:
    mutex_unlock(&port_mutex);

    return ret;
}

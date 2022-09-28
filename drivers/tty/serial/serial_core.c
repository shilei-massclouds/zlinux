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
#include <linux/gpio/consumer.h>
#if 0
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

static const char *uart_type(struct uart_port *port)
{
    const char *str = NULL;

    if (port->ops->type)
        str = port->ops->type(port);

    if (!str)
        str = "unknown";

    return str;
}

static inline void
uart_report_port(struct uart_driver *drv, struct uart_port *port)
{
    char address[64];

    switch (port->iotype) {
    case UPIO_PORT:
        snprintf(address, sizeof(address), "I/O 0x%lx", port->iobase);
        break;
    case UPIO_HUB6:
        snprintf(address, sizeof(address),
             "I/O 0x%lx offset 0x%x", port->iobase, port->hub6);
        break;
    case UPIO_MEM:
    case UPIO_MEM16:
    case UPIO_MEM32:
    case UPIO_MEM32BE:
    case UPIO_AU:
    case UPIO_TSI:
        snprintf(address, sizeof(address),
             "MMIO 0x%llx", (unsigned long long)port->mapbase);
        break;
    default:
        strlcpy(address, "*unknown*", sizeof(address));
        break;
    }

    pr_info("%s%s%s at %s (irq = %d, base_baud = %d) is a %s\n",
           port->dev ? dev_name(port->dev) : "",
           port->dev ? ": " : "",
           port->name,
           address, port->irq, port->uartclk / 16, uart_type(port));

    /* The magic multiplier feature is a bit obscure, so report it too.  */
    if (port->flags & UPF_MAGIC_MULTIPLIER)
        pr_info("%s%s%s extra baud rates supported: %d, %d",
            port->dev ? dev_name(port->dev) : "",
            port->dev ? ": " : "",
            port->name,
            port->uartclk / 8, port->uartclk / 4);
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

    /*
     * Now do the auto configuration stuff.  Note that config_port
     * is expected to claim the resources and map the port for us.
     */
    flags = 0;
    if (port->flags & UPF_AUTO_IRQ)
        flags |= UART_CONFIG_IRQ;
    if (port->flags & UPF_BOOT_AUTOCONF) {
        if (!(port->flags & UPF_FIXED_TYPE)) {
            port->type = PORT_UNKNOWN;
            flags |= UART_CONFIG_TYPE;
        }
        port->ops->config_port(port, flags);
    }

    if (port->type != PORT_UNKNOWN) {
        unsigned long flags;

        uart_report_port(drv, port);

#if 0
        /* Power up port for set_mctrl() */
        uart_change_pm(state, UART_PM_STATE_ON);
#endif

        /*
         * Ensure that the modem control lines are de-activated.
         * keep the DTR setting that is set in uart_set_options()
         * We probably don't need a spinlock around this, but
         */
        spin_lock_irqsave(&port->lock, flags);
        port->mctrl &= TIOCM_DTR;
        if (port->rs485.flags & SER_RS485_ENABLED &&
            !(port->rs485.flags & SER_RS485_RTS_AFTER_SEND))
            port->mctrl |= TIOCM_RTS;
        port->ops->set_mctrl(port, port->mctrl);
        spin_unlock_irqrestore(&port->lock, flags);

        printk("%s: 1\n", __func__);
        /*
         * If this driver supports console, and it hasn't been
         * successfully registered yet, try to re-register it.
         * It may be that the port was not available.
         */
        if (port->cons && !(port->cons->flags & CON_ENABLED))
            register_console(port->cons);
        printk("%s: 2\n", __func__);

#if 0
        /*
         * Power down all ports by default, except the
         * console if we have one.
         */
        if (!uart_console(port))
            uart_change_pm(state, UART_PM_STATE_OFF);
#endif
    }
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
    printk("###### %s: 1 ...\n", __func__);
    uart_configure_port(drv, state, uport);

    printk("###### %s: 1.2 ...\n", __func__);
    port->console = uart_console(uport);

    printk("###### %s: 2 ...\n", __func__);
    num_groups = 2;
    if (uport->attr_group)
        num_groups++;

    printk("###### %s: 3 ...\n", __func__);
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
    printk("###### %s: ! ...\n", __func__);
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

/**
 * uart_get_rs485_mode() - retrieve rs485 properties for given uart
 * @port: uart device's target port
 *
 * This function implements the device tree binding described in
 * Documentation/devicetree/bindings/serial/rs485.txt.
 */
int uart_get_rs485_mode(struct uart_port *port)
{
    struct serial_rs485 *rs485conf = &port->rs485;
    struct device *dev = port->dev;
    u32 rs485_delay[2];
    int ret;

    ret = device_property_read_u32_array(dev, "rs485-rts-delay",
                                         rs485_delay, 2);
    if (!ret) {
        rs485conf->delay_rts_before_send = rs485_delay[0];
        rs485conf->delay_rts_after_send = rs485_delay[1];
    } else {
        rs485conf->delay_rts_before_send = 0;
        rs485conf->delay_rts_after_send = 0;
    }

    /*
     * Clear full-duplex and enabled flags, set RTS polarity to active high
     * to get to a defined state with the following properties:
     */
    rs485conf->flags &= ~(SER_RS485_RX_DURING_TX | SER_RS485_ENABLED |
                          SER_RS485_TERMINATE_BUS |
                          SER_RS485_RTS_AFTER_SEND);
    rs485conf->flags |= SER_RS485_RTS_ON_SEND;

    if (device_property_read_bool(dev, "rs485-rx-during-tx"))
        rs485conf->flags |= SER_RS485_RX_DURING_TX;

    if (device_property_read_bool(dev,
                                  "linux,rs485-enabled-at-boot-time"))
        rs485conf->flags |= SER_RS485_ENABLED;

    if (device_property_read_bool(dev, "rs485-rts-active-low")) {
        rs485conf->flags &= ~SER_RS485_RTS_ON_SEND;
        rs485conf->flags |= SER_RS485_RTS_AFTER_SEND;
    }

#if 0
    /*
     * Disabling termination by default is the safe choice:  Else if many
     * bus participants enable it, no communication is possible at all.
     * Works fine for short cables and users may enable for longer cables.
     */
    port->rs485_term_gpio = devm_gpiod_get_optional(dev, "rs485-term",
                                                    GPIOD_OUT_LOW);
    if (IS_ERR(port->rs485_term_gpio)) {
        ret = PTR_ERR(port->rs485_term_gpio);
        port->rs485_term_gpio = NULL;
        return dev_err_probe(dev, ret, "Cannot get rs485-term-gpios\n");
    }
#endif

    return 0;
}
EXPORT_SYMBOL_GPL(uart_get_rs485_mode);

/**
 *  uart_parse_earlycon - Parse earlycon options
 *  @p:   ptr to 2nd field (ie., just beyond '<name>,')
 *  @iotype:  ptr for decoded iotype (out)
 *  @addr:    ptr for decoded mapbase/iobase (out)
 *  @options: ptr for <options> field; NULL if not present (out)
 *
 *  Decodes earlycon kernel command line parameters of the form
 *     earlycon=<name>,io|mmio|mmio16|mmio32|mmio32be|mmio32native,<addr>,<options>
 *     console=<name>,io|mmio|mmio16|mmio32|mmio32be|mmio32native,<addr>,<options>
 *
 *  The optional form
 *
 *     earlycon=<name>,0x<addr>,<options>
 *     console=<name>,0x<addr>,<options>
 *
 *  is also accepted; the returned @iotype will be UPIO_MEM.
 *
 *  Returns 0 on success or -EINVAL on failure
 */
int uart_parse_earlycon(char *p, unsigned char *iotype,
                        resource_size_t *addr, char **options)
{
    if (strncmp(p, "mmio,", 5) == 0) {
        *iotype = UPIO_MEM;
        p += 5;
    } else if (strncmp(p, "mmio16,", 7) == 0) {
        *iotype = UPIO_MEM16;
        p += 7;
    } else if (strncmp(p, "mmio32,", 7) == 0) {
        *iotype = UPIO_MEM32;
        p += 7;
    } else if (strncmp(p, "mmio32be,", 9) == 0) {
        *iotype = UPIO_MEM32BE;
        p += 9;
    } else if (strncmp(p, "mmio32native,", 13) == 0) {
        *iotype = IS_ENABLED(CONFIG_CPU_BIG_ENDIAN) ?
            UPIO_MEM32BE : UPIO_MEM32;
        p += 13;
    } else if (strncmp(p, "io,", 3) == 0) {
        *iotype = UPIO_PORT;
        p += 3;
    } else if (strncmp(p, "0x", 2) == 0) {
        *iotype = UPIO_MEM;
    } else {
        return -EINVAL;
    }

    panic("%s: END!\n", __func__);
}

/**
 *  uart_parse_options - Parse serial port baud/parity/bits/flow control.
 *  @options: pointer to option string
 *  @baud: pointer to an 'int' variable for the baud rate.
 *  @parity: pointer to an 'int' variable for the parity.
 *  @bits: pointer to an 'int' variable for the number of data bits.
 *  @flow: pointer to an 'int' variable for the flow control character.
 *
 *  uart_parse_options decodes a string containing the serial console
 *  options.  The format of the string is <baud><parity><bits><flow>,
 *  eg: 115200n8r
 */
void
uart_parse_options(const char *options, int *baud, int *parity,
                   int *bits, int *flow)
{
    const char *s = options;

    *baud = simple_strtoul(s, NULL, 10);
    while (*s >= '0' && *s <= '9')
        s++;
    if (*s)
        *parity = *s++;
    if (*s)
        *bits = *s++ - '0';
    if (*s)
        *flow = *s;
}

/**
 *  uart_set_options - setup the serial console parameters
 *  @port: pointer to the serial ports uart_port structure
 *  @co: console pointer
 *  @baud: baud rate
 *  @parity: parity character - 'n' (none), 'o' (odd), 'e' (even)
 *  @bits: number of data bits
 *  @flow: flow control character - 'r' (rts)
 */
int
uart_set_options(struct uart_port *port, struct console *co,
                 int baud, int parity, int bits, int flow)
{
    struct ktermios termios;
    static struct ktermios dummy;

    /*
     * Ensure that the serial-console lock is initialised early.
     *
     * Note that the console-enabled check is needed because of kgdboc,
     * which can end up calling uart_set_options() for an already enabled
     * console via tty_find_polling_driver() and uart_poll_init().
     */
    if (!uart_console_enabled(port) && !port->console_reinit)
        uart_port_spin_lock_init(port);

    memset(&termios, 0, sizeof(struct ktermios));

    termios.c_cflag |= CREAD | HUPCL | CLOCAL;
    tty_termios_encode_baud_rate(&termios, baud, baud);

    if (bits == 7)
        termios.c_cflag |= CS7;
    else
        termios.c_cflag |= CS8;

    switch (parity) {
    case 'o': case 'O':
        termios.c_cflag |= PARODD;
        fallthrough;
    case 'e': case 'E':
        termios.c_cflag |= PARENB;
        break;
    }

    if (flow == 'r')
        termios.c_cflag |= CRTSCTS;

    /*
     * some uarts on other side don't support no flow control.
     * So we set * DTR in host uart to make them happy
     */
    port->mctrl |= TIOCM_DTR;

    port->ops->set_termios(port, &termios, &dummy);
    /*
     * Allow the setting of the UART parameters with a NULL console
     * too:
     */
    if (co) {
        co->cflag = termios.c_cflag;
        co->ispeed = termios.c_ispeed;
        co->ospeed = termios.c_ospeed;
    }

    return 0;
}

/**
 *  uart_get_baud_rate - return baud rate for a particular port
 *  @port: uart_port structure describing the port in question.
 *  @termios: desired termios settings.
 *  @old: old termios (or NULL)
 *  @min: minimum acceptable baud rate
 *  @max: maximum acceptable baud rate
 *
 *  Decode the termios structure into a numeric baud rate,
 *  taking account of the magic 38400 baud rate (with spd_*
 *  flags), and mapping the %B0 rate to 9600 baud.
 *
 *  If the new baud rate is invalid, try the old termios setting.
 *  If it's still invalid, we try 9600 baud.
 *
 *  Update the @termios structure to reflect the baud rate
 *  we're actually going to be using. Don't do this for the case
 *  where B0 is requested ("hang up").
 */
unsigned int
uart_get_baud_rate(struct uart_port *port, struct ktermios *termios,
                   struct ktermios *old,
                   unsigned int min, unsigned int max)
{
    unsigned int try;
    unsigned int baud;
    unsigned int altbaud;
    int hung_up = 0;
    upf_t flags = port->flags & UPF_SPD_MASK;

    switch (flags) {
    case UPF_SPD_HI:
        altbaud = 57600;
        break;
    case UPF_SPD_VHI:
        altbaud = 115200;
        break;
    case UPF_SPD_SHI:
        altbaud = 230400;
        break;
    case UPF_SPD_WARP:
        altbaud = 460800;
        break;
    default:
        altbaud = 38400;
        break;
    }

    for (try = 0; try < 2; try++) {
        baud = tty_termios_baud_rate(termios);

        /*
         * The spd_hi, spd_vhi, spd_shi, spd_warp kludge...
         * Die! Die! Die!
         */
        if (try == 0 && baud == 38400)
            baud = altbaud;

        /*
         * Special case: B0 rate.
         */
        if (baud == 0) {
            hung_up = 1;
            baud = 9600;
        }

        if (baud >= min && baud <= max)
            return baud;

        /*
         * Oops, the quotient was zero.  Try again with
         * the old baud rate if possible.
         */
        termios->c_cflag &= ~CBAUD;
        if (old) {
            baud = tty_termios_baud_rate(old);
            if (!hung_up)
                tty_termios_encode_baud_rate(termios, baud, baud);
            old = NULL;
            continue;
        }

        /*
         * As a last resort, if the range cannot be met then clip to
         * the nearest chip supported rate.
         */
        if (!hung_up) {
            if (baud <= min)
                tty_termios_encode_baud_rate(termios, min + 1, min + 1);
            else
                tty_termios_encode_baud_rate(termios, max - 1, max - 1);
        }
    }
    /* Should never happen */
    WARN_ON(1);
    return 0;
}

/**
 *  uart_get_divisor - return uart clock divisor
 *  @port: uart_port structure describing the port.
 *  @baud: desired baud rate
 *
 *  Calculate the uart clock divisor for the port.
 */
unsigned int
uart_get_divisor(struct uart_port *port, unsigned int baud)
{
    unsigned int quot;

    /*
     * Old custom speed handling.
     */
    if (baud == 38400 && (port->flags & UPF_SPD_MASK) == UPF_SPD_CUST)
        quot = port->custom_divisor;
    else
        quot = DIV_ROUND_CLOSEST(port->uartclk, 16 * baud);

    return quot;
}
EXPORT_SYMBOL(uart_get_divisor);

/**
 *  uart_update_timeout - update per-port FIFO timeout.
 *  @port:  uart_port structure describing the port
 *  @cflag: termios cflag value
 *  @baud:  speed of the port
 *
 *  Set the port FIFO timeout value.  The @cflag value should
 *  reflect the actual hardware settings.
 */
void
uart_update_timeout(struct uart_port *port, unsigned int cflag,
                    unsigned int baud)
{
    unsigned int size;

    size = tty_get_frame_size(cflag) * port->fifosize;

    /*
     * Figure the timeout to send the above number of bits.
     * Add .02 seconds of slop
     */
    port->timeout = (HZ * size) / baud + HZ/50;
}
EXPORT_SYMBOL(uart_update_timeout);

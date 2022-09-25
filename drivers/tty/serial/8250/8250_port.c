// SPDX-License-Identifier: GPL-2.0+
/*
 *  Base port operations for 8250/16550-type serial ports
 *
 *  Based on drivers/char/serial.c, by Linus Torvalds, Theodore Ts'o.
 *  Split from 8250_core.c, Copyright (C) 2001 Russell King.
 *
 * A note about mapbase / membase
 *
 *  mapbase is the physical address of the IO port.
 *  membase is an 'ioremapped' cookie.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/console.h>
#if 0
#include <linux/gpio/consumer.h>
#include <linux/sysrq.h>
#endif
#include <linux/delay.h>
#include <linux/platform_device.h>
#if 0
#include <linux/tty.h>
#include <linux/ratelimit.h>
#include <linux/tty_flip.h>
#endif
#include <linux/serial.h>
#include <linux/serial_8250.h>
#include <linux/nmi.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
//#include <linux/pm_runtime.h>
#include <linux/ktime.h>

#include <asm/io.h>
#include <asm/irq.h>

#include "8250.h"

/**
 * serial8250_em485_config() - generic ->rs485_config() callback
 * @port: uart port
 * @rs485: rs485 settings
 *
 * Generic callback usable by 8250 uart drivers to activate rs485 settings
 * if the uart is incapable of driving RTS as a Transmit Enable signal in
 * hardware, relying on software emulation instead.
 */
int serial8250_em485_config(struct uart_port *port,
                            struct serial_rs485 *rs485)
{
    panic("%s: END!\n", __func__);
}

/**
 * serial8250_em485_start_tx() - generic ->rs485_start_tx() callback
 * @up: uart 8250 port
 *
 * Generic callback usable by 8250 uart drivers to start rs485 transmission.
 * Assumes that setting the RTS bit in the MCR register means RTS is high.
 * (Some chips use inverse semantics.)  Further assumes that reception is
 * stoppable by disabling the UART_IER_RDI interrupt.  (Some chips set the
 * UART_LSR_DR bit even when UART_IER_RDI is disabled, foiling this approach.)
 */
void serial8250_em485_start_tx(struct uart_8250_port *up)
{
#if 0
    unsigned char mcr = serial8250_in_MCR(up);

    if (!(up->port.rs485.flags & SER_RS485_RX_DURING_TX))
        serial8250_stop_rx(&up->port);

    if (up->port.rs485.flags & SER_RS485_RTS_ON_SEND)
        mcr |= UART_MCR_RTS;
    else
        mcr &= ~UART_MCR_RTS;
    serial8250_out_MCR(up, mcr);
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(serial8250_em485_start_tx);

/**
 * serial8250_em485_stop_tx() - generic ->rs485_stop_tx() callback
 * @p: uart 8250 port
 *
 * Generic callback usable by 8250 uart drivers to stop rs485 transmission.
 */
void serial8250_em485_stop_tx(struct uart_8250_port *p)
{
#if 0
    unsigned char mcr = serial8250_in_MCR(p);

    if (p->port.rs485.flags & SER_RS485_RTS_AFTER_SEND)
        mcr |= UART_MCR_RTS;
    else
        mcr &= ~UART_MCR_RTS;
    serial8250_out_MCR(p, mcr);

    /*
     * Empty the RX FIFO, we are not interested in anything
     * received during the half-duplex transmission.
     * Enable previously disabled RX interrupts.
     */
    if (!(p->port.rs485.flags & SER_RS485_RX_DURING_TX)) {
        serial8250_clear_and_reinit_fifos(p);

        p->ier |= UART_IER_RLSI | UART_IER_RDI;
        serial_port_out(&p->port, UART_IER, p->ier);
    }
#endif
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(serial8250_em485_stop_tx);

static unsigned int serial8250_tx_empty(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static void serial8250_set_mctrl(struct uart_port *port,
                                 unsigned int mctrl)
{
    panic("%s: END!\n", __func__);
}

static unsigned int serial8250_get_mctrl(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static void serial8250_stop_tx(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static void serial8250_start_tx(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static void serial8250_throttle(struct uart_port *port)
{
    port->throttle(port);
}

static void serial8250_unthrottle(struct uart_port *port)
{
    port->unthrottle(port);
}

static void serial8250_stop_rx(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static void serial8250_enable_ms(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static void serial8250_break_ctl(struct uart_port *port,
                                 int break_state)
{
    panic("%s: END!\n", __func__);
}

static int serial8250_startup(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static void serial8250_shutdown(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static void
serial8250_set_termios(struct uart_port *port, struct ktermios *termios,
               struct ktermios *old)
{
    panic("%s: END!\n", __func__);
}

static void
serial8250_set_ldisc(struct uart_port *port, struct ktermios *termios)
{
    panic("%s: END!\n", __func__);
}

static const char *serial8250_type(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static void serial8250_release_port(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static int serial8250_request_port(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static void serial8250_config_port(struct uart_port *port, int flags)
{
    panic("%s: END!\n", __func__);
}

static int
serial8250_verify_port(struct uart_port *port,
                       struct serial_struct *ser)
{
    panic("%s: END!\n", __func__);
}

static void
serial8250_pm(struct uart_port *port, unsigned int state,
              unsigned int oldstate)
{
    panic("%s: END!\n", __func__);
}

static const struct uart_ops serial8250_pops = {
    .tx_empty   = serial8250_tx_empty,
    .set_mctrl  = serial8250_set_mctrl,
    .get_mctrl  = serial8250_get_mctrl,
    .stop_tx    = serial8250_stop_tx,
    .start_tx   = serial8250_start_tx,
    .throttle   = serial8250_throttle,
    .unthrottle = serial8250_unthrottle,
    .stop_rx    = serial8250_stop_rx,
    .enable_ms  = serial8250_enable_ms,
    .break_ctl  = serial8250_break_ctl,
    .startup    = serial8250_startup,
    .shutdown   = serial8250_shutdown,
    .set_termios    = serial8250_set_termios,
    .set_ldisc  = serial8250_set_ldisc,
    .pm         = serial8250_pm,
    .type       = serial8250_type,
    .release_port   = serial8250_release_port,
    .request_port   = serial8250_request_port,
    .config_port    = serial8250_config_port,
    .verify_port    = serial8250_verify_port,
};

/* Uart divisor latch read */
static int default_serial_dl_read(struct uart_8250_port *up)
{
    /* Assign these in pieces to truncate any bits above 7.  */
    unsigned char dll = serial_in(up, UART_DLL);
    unsigned char dlm = serial_in(up, UART_DLM);

    return dll | dlm << 8;
}

/* Uart divisor latch write */
static void default_serial_dl_write(struct uart_8250_port *up,
                                    int value)
{
    serial_out(up, UART_DLL, value & 0xff);
    serial_out(up, UART_DLM, value >> 8 & 0xff);
}

static unsigned int hub6_serial_in(struct uart_port *p, int offset)
{
    offset = offset << p->regshift;
    outb(p->hub6 - 1 + offset, p->iobase);
    return inb(p->iobase + 1);
}

static void hub6_serial_out(struct uart_port *p, int offset, int value)
{
    offset = offset << p->regshift;
    outb(p->hub6 - 1 + offset, p->iobase);
    outb(value, p->iobase + 1);
}

static unsigned int io_serial_in(struct uart_port *p, int offset)
{
    offset = offset << p->regshift;
    return inb(p->iobase + offset);
}

static void io_serial_out(struct uart_port *p, int offset, int value)
{
    offset = offset << p->regshift;
    outb(value, p->iobase + offset);
}

static int serial8250_default_handle_irq(struct uart_port *port)
{
#if 0
    struct uart_8250_port *up = up_to_u8250p(port);
    unsigned int iir;
    int ret;

    serial8250_rpm_get(up);

    iir = serial_port_in(port, UART_IIR);
    ret = serial8250_handle_irq(port, iir);

    serial8250_rpm_put(up);
    return ret;
#endif
    panic("%s: END!\n", __func__);
}

static void set_io_from_upio(struct uart_port *p)
{
    struct uart_8250_port *up = up_to_u8250p(p);

    up->dl_read = default_serial_dl_read;
    up->dl_write = default_serial_dl_write;

    switch (p->iotype) {
    case UPIO_HUB6:
#if 0
        p->serial_in = hub6_serial_in;
        p->serial_out = hub6_serial_out;
#endif
        panic("%s: UPIO_HUB6!\n", __func__);
        break;

    case UPIO_MEM:
#if 0
        p->serial_in = mem_serial_in;
        p->serial_out = mem_serial_out;
#endif
        panic("%s: UPIO_MEM!\n", __func__);
        break;

    case UPIO_MEM16:
#if 0
        p->serial_in = mem16_serial_in;
        p->serial_out = mem16_serial_out;
#endif
        panic("%s: UPIO_MEM16!\n", __func__);
        break;

    case UPIO_MEM32:
#if 0
        p->serial_in = mem32_serial_in;
        p->serial_out = mem32_serial_out;
#endif
        panic("%s: UPIO_MEM32!\n", __func__);
        break;

    case UPIO_MEM32BE:
#if 0
        p->serial_in = mem32be_serial_in;
        p->serial_out = mem32be_serial_out;
#endif
        panic("%s: UPIO_MEM32BE!\n", __func__);
        break;

    default:
        p->serial_in = io_serial_in;
        p->serial_out = io_serial_out;
        break;
    }
    /* Remember loaded iotype */
    up->cur_iotype = p->iotype;
    p->handle_irq = serial8250_default_handle_irq;
}

void serial8250_set_defaults(struct uart_8250_port *up)
{
    struct uart_port *port = &up->port;

    if (up->port.flags & UPF_FIXED_TYPE) {
#if 0
        unsigned int type = up->port.type;

        if (!up->port.fifosize)
            up->port.fifosize = uart_config[type].fifo_size;
        if (!up->tx_loadsz)
            up->tx_loadsz = uart_config[type].tx_loadsz;
        if (!up->capabilities)
            up->capabilities = uart_config[type].flags;
#endif
        panic("%s: UPF_FIXED_TYPE!\n", __func__);
    }

    set_io_from_upio(port);

    /* default dma handlers */
    if (up->dma) {
#if 0
        if (!up->dma->tx_dma)
            up->dma->tx_dma = serial8250_tx_dma;
        if (!up->dma->rx_dma)
            up->dma->rx_dma = serial8250_rx_dma;
#endif
        panic("%s: up->dma!\n", __func__);
    }
}
EXPORT_SYMBOL_GPL(serial8250_set_defaults);

void serial8250_init_port(struct uart_8250_port *up)
{
    struct uart_port *port = &up->port;

    spin_lock_init(&port->lock);
    port->ops = &serial8250_pops;
    port->has_sysrq = 1;

    up->cur_iotype = 0xFF;
}
EXPORT_SYMBOL_GPL(serial8250_init_port);

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

/*
 * Here we define the default xmit fifo size used for each type of UART.
 */
static const struct serial8250_config uart_config[] = {
    [PORT_UNKNOWN] = {
        .name       = "unknown",
        .fifo_size  = 1,
        .tx_loadsz  = 1,
    },
    [PORT_8250] = {
        .name       = "8250",
        .fifo_size  = 1,
        .tx_loadsz  = 1,
    },
    [PORT_16450] = {
        .name       = "16450",
        .fifo_size  = 1,
        .tx_loadsz  = 1,
    },
    [PORT_16550] = {
        .name       = "16550",
        .fifo_size  = 1,
        .tx_loadsz  = 1,
    },
    [PORT_16550A] = {
        .name       = "16550A",
        .fifo_size  = 16,
        .tx_loadsz  = 16,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10,
        .rxtrig_bytes   = {1, 4, 8, 14},
        .flags      = UART_CAP_FIFO,
    },
    [PORT_CIRRUS] = {
        .name       = "Cirrus",
        .fifo_size  = 1,
        .tx_loadsz  = 1,
    },
    [PORT_16650] = {
        .name       = "ST16650",
        .fifo_size  = 1,
        .tx_loadsz  = 1,
        .flags      = UART_CAP_FIFO | UART_CAP_EFR | UART_CAP_SLEEP,
    },
    [PORT_16650V2] = {
        .name       = "ST16650V2",
        .fifo_size  = 32,
        .tx_loadsz  = 16,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_01 |
                  UART_FCR_T_TRIG_00,
        .rxtrig_bytes   = {8, 16, 24, 28},
        .flags      = UART_CAP_FIFO | UART_CAP_EFR | UART_CAP_SLEEP,
    },
    [PORT_16750] = {
        .name       = "TI16750",
        .fifo_size  = 64,
        .tx_loadsz  = 64,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10 |
                  UART_FCR7_64BYTE,
        .rxtrig_bytes   = {1, 16, 32, 56},
        .flags      = UART_CAP_FIFO | UART_CAP_SLEEP | UART_CAP_AFE,
    },
    [PORT_STARTECH] = {
        .name       = "Startech",
        .fifo_size  = 1,
        .tx_loadsz  = 1,
    },
    [PORT_16C950] = {
        .name       = "16C950/954",
        .fifo_size  = 128,
        .tx_loadsz  = 128,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_01,
        .rxtrig_bytes   = {16, 32, 112, 120},
        /* UART_CAP_EFR breaks billionon CF bluetooth card. */
        .flags      = UART_CAP_FIFO | UART_CAP_SLEEP,
    },
    [PORT_16654] = {
        .name       = "ST16654",
        .fifo_size  = 64,
        .tx_loadsz  = 32,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_01 |
                  UART_FCR_T_TRIG_10,
        .rxtrig_bytes   = {8, 16, 56, 60},
        .flags      = UART_CAP_FIFO | UART_CAP_EFR | UART_CAP_SLEEP,
    },
    [PORT_16850] = {
        .name       = "XR16850",
        .fifo_size  = 128,
        .tx_loadsz  = 128,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10,
        .flags      = UART_CAP_FIFO | UART_CAP_EFR | UART_CAP_SLEEP,
    },
    [PORT_RSA] = {
        .name       = "RSA",
        .fifo_size  = 2048,
        .tx_loadsz  = 2048,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_11,
        .flags      = UART_CAP_FIFO,
    },
    [PORT_NS16550A] = {
        .name       = "NS16550A",
        .fifo_size  = 16,
        .tx_loadsz  = 16,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10,
        .flags      = UART_CAP_FIFO | UART_NATSEMI,
    },
    [PORT_XSCALE] = {
        .name       = "XScale",
        .fifo_size  = 32,
        .tx_loadsz  = 32,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10,
        .flags      = UART_CAP_FIFO | UART_CAP_UUE | UART_CAP_RTOIE,
    },
    [PORT_OCTEON] = {
        .name       = "OCTEON",
        .fifo_size  = 64,
        .tx_loadsz  = 64,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10,
        .flags      = UART_CAP_FIFO,
    },
    [PORT_AR7] = {
        .name       = "AR7",
        .fifo_size  = 16,
        .tx_loadsz  = 16,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_00,
        .flags      = UART_CAP_FIFO /* | UART_CAP_AFE */,
    },
    [PORT_U6_16550A] = {
        .name       = "U6_16550A",
        .fifo_size  = 64,
        .tx_loadsz  = 64,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10,
        .flags      = UART_CAP_FIFO | UART_CAP_AFE,
    },
    [PORT_TEGRA] = {
        .name       = "Tegra",
        .fifo_size  = 32,
        .tx_loadsz  = 8,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_01 |
                  UART_FCR_T_TRIG_01,
        .rxtrig_bytes   = {1, 4, 8, 14},
        .flags      = UART_CAP_FIFO | UART_CAP_RTOIE,
    },
    [PORT_XR17D15X] = {
        .name       = "XR17D15X",
        .fifo_size  = 64,
        .tx_loadsz  = 64,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10,
        .flags      = UART_CAP_FIFO | UART_CAP_AFE | UART_CAP_EFR |
                  UART_CAP_SLEEP,
    },
    [PORT_XR17V35X] = {
        .name       = "XR17V35X",
        .fifo_size  = 256,
        .tx_loadsz  = 256,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_11 |
                  UART_FCR_T_TRIG_11,
        .flags      = UART_CAP_FIFO | UART_CAP_AFE | UART_CAP_EFR |
                  UART_CAP_SLEEP,
    },
    [PORT_LPC3220] = {
        .name       = "LPC3220",
        .fifo_size  = 64,
        .tx_loadsz  = 32,
        .fcr        = UART_FCR_DMA_SELECT | UART_FCR_ENABLE_FIFO |
                  UART_FCR_R_TRIG_00 | UART_FCR_T_TRIG_00,
        .flags      = UART_CAP_FIFO,
    },
    [PORT_BRCM_TRUMANAGE] = {
        .name       = "TruManage",
        .fifo_size  = 1,
        .tx_loadsz  = 1024,
        .flags      = UART_CAP_HFIFO,
    },
    [PORT_8250_CIR] = {
        .name       = "CIR port"
    },
    [PORT_ALTR_16550_F32] = {
        .name       = "Altera 16550 FIFO32",
        .fifo_size  = 32,
        .tx_loadsz  = 32,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10,
        .rxtrig_bytes   = {1, 8, 16, 30},
        .flags      = UART_CAP_FIFO | UART_CAP_AFE,
    },
    [PORT_ALTR_16550_F64] = {
        .name       = "Altera 16550 FIFO64",
        .fifo_size  = 64,
        .tx_loadsz  = 64,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10,
        .rxtrig_bytes   = {1, 16, 32, 62},
        .flags      = UART_CAP_FIFO | UART_CAP_AFE,
    },
    [PORT_ALTR_16550_F128] = {
        .name       = "Altera 16550 FIFO128",
        .fifo_size  = 128,
        .tx_loadsz  = 128,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10,
        .rxtrig_bytes   = {1, 32, 64, 126},
        .flags      = UART_CAP_FIFO | UART_CAP_AFE,
    },
    /*
     * tx_loadsz is set to 63-bytes instead of 64-bytes to implement
     * workaround of errata A-008006 which states that tx_loadsz should
     * be configured less than Maximum supported fifo bytes.
     */
    [PORT_16550A_FSL64] = {
        .name       = "16550A_FSL64",
        .fifo_size  = 64,
        .tx_loadsz  = 63,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10 |
                  UART_FCR7_64BYTE,
        .flags      = UART_CAP_FIFO,
    },
    [PORT_RT2880] = {
        .name       = "Palmchip BK-3103",
        .fifo_size  = 16,
        .tx_loadsz  = 16,
        .fcr        = UART_FCR_ENABLE_FIFO | UART_FCR_R_TRIG_10,
        .rxtrig_bytes   = {1, 4, 8, 14},
        .flags      = UART_CAP_FIFO,
    },
};

static void set_io_from_upio(struct uart_port *p);

static unsigned int serial8250_port_size(struct uart_8250_port *pt)
{
    if (pt->port.mapsize)
        return pt->port.mapsize;
    if (pt->port.iotype == UPIO_AU) {
        if (pt->port.type == PORT_RT2880)
            return 0x100;
        return 0x1000;
    }

    return 8 << pt->port.regshift;
}

/*
 * Resource handling.
 */
static int serial8250_request_std_resource(struct uart_8250_port *up)
{
    unsigned int size = serial8250_port_size(up);
    struct uart_port *port = &up->port;
    int ret = 0;

    switch (port->iotype) {
    case UPIO_AU:
    case UPIO_TSI:
    case UPIO_MEM32:
    case UPIO_MEM32BE:
    case UPIO_MEM16:
    case UPIO_MEM:
        if (!port->mapbase)
            break;

        if (!request_mem_region(port->mapbase, size, "serial")) {
            ret = -EBUSY;
            break;
        }

        if (port->flags & UPF_IOREMAP) {
            port->membase = ioremap(port->mapbase, size);
            if (!port->membase) {
                release_mem_region(port->mapbase, size);
                ret = -ENOMEM;
            }
        }
        break;

    case UPIO_HUB6:
    case UPIO_PORT:
#if 0
        if (!request_region(port->iobase, size, "serial"))
            ret = -EBUSY;
#endif
        panic("%s: UPIO_PORT!\n", __func__);
        break;
    }
    return ret;
}

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

void serial8250_do_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
    struct uart_8250_port *up = up_to_u8250p(port);
    unsigned char mcr;

    mcr = serial8250_TIOCM_to_MCR(mctrl);

    mcr |= up->mcr;

    serial8250_out_MCR(up, mcr);
}
EXPORT_SYMBOL_GPL(serial8250_do_set_mctrl);

static void serial8250_set_mctrl(struct uart_port *port,
                                 unsigned int mctrl)
{
    if (port->set_mctrl)
        port->set_mctrl(port, mctrl);
    else
        serial8250_do_set_mctrl(port, mctrl);
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

static unsigned char
serial8250_compute_lcr(struct uart_8250_port *up, tcflag_t c_cflag)
{
    unsigned char cval;

    cval = UART_LCR_WLEN(tty_get_char_size(c_cflag));

    if (c_cflag & CSTOPB)
        cval |= UART_LCR_STOP;
    if (c_cflag & PARENB) {
        cval |= UART_LCR_PARITY;
        if (up->bugs & UART_BUG_PARITY)
            up->fifo_bug = true;
    }
    if (!(c_cflag & PARODD))
        cval |= UART_LCR_EPAR;
#ifdef CMSPAR
    if (c_cflag & CMSPAR)
        cval |= UART_LCR_SPAR;
#endif

    return cval;
}

static unsigned int
serial8250_get_baud_rate(struct uart_port *port,
                         struct ktermios *termios,
                         struct ktermios *old)
{
    unsigned int tolerance = port->uartclk / 100;
    unsigned int min;
    unsigned int max;

    /*
     * Handle magic divisors for baud rates above baud_base on SMSC
     * Super I/O chips.  Enable custom rates of clk/4 and clk/8, but
     * disable divisor values beyond 32767, which are unavailable.
     */
    if (port->flags & UPF_MAGIC_MULTIPLIER) {
        min = port->uartclk / 16 / UART_DIV_MAX >> 1;
        max = (port->uartclk + tolerance) / 4;
    } else {
        min = port->uartclk / 16 / UART_DIV_MAX;
        max = (port->uartclk + tolerance) / 16;
    }

    /*
     * Ask the core to calculate the divisor for us.
     * Allow 1% tolerance at the upper limit so uart clks marginally
     * slower than nominal still match standard baud rates without
     * causing transmission errors.
     */
    return uart_get_baud_rate(port, termios, old, min, max);
}

static unsigned int
serial8250_do_get_divisor(struct uart_port *port, unsigned int baud,
                          unsigned int *frac)
{
    upf_t magic_multiplier = port->flags & UPF_MAGIC_MULTIPLIER;
    struct uart_8250_port *up = up_to_u8250p(port);
    unsigned int quot;

    /*
     * Handle magic divisors for baud rates above baud_base on SMSC
     * Super I/O chips.  We clamp custom rates from clk/6 and clk/12
     * up to clk/4 (0x8001) and clk/8 (0x8002) respectively.  These
     * magic divisors actually reprogram the baud rate generator's
     * reference clock derived from chips's 14.318MHz clock input.
     *
     * Documentation claims that with these magic divisors the base
     * frequencies of 7.3728MHz and 3.6864MHz are used respectively
     * for the extra baud rates of 460800bps and 230400bps rather
     * than the usual base frequency of 1.8462MHz.  However empirical
     * evidence contradicts that.
     *
     * Instead bit 7 of the DLM register (bit 15 of the divisor) is
     * effectively used as a clock prescaler selection bit for the
     * base frequency of 7.3728MHz, always used.  If set to 0, then
     * the base frequency is divided by 4 for use by the Baud Rate
     * Generator, for the usual arrangement where the value of 1 of
     * the divisor produces the baud rate of 115200bps.  Conversely,
     * if set to 1 and high-speed operation has been enabled with the
     * Serial Port Mode Register in the Device Configuration Space,
     * then the base frequency is supplied directly to the Baud Rate
     * Generator, so for the divisor values of 0x8001, 0x8002, 0x8003,
     * 0x8004, etc. the respective baud rates produced are 460800bps,
     * 230400bps, 153600bps, 115200bps, etc.
     *
     * In all cases only low 15 bits of the divisor are used to divide
     * the baud base and therefore 32767 is the maximum divisor value
     * possible, even though documentation says that the programmable
     * Baud Rate Generator is capable of dividing the internal PLL
     * clock by any divisor from 1 to 65535.
     */
    if (magic_multiplier && baud >= port->uartclk / 6)
        quot = 0x8001;
    else if (magic_multiplier && baud >= port->uartclk / 12)
        quot = 0x8002;
    else
        quot = uart_get_divisor(port, baud);

    /*
     * Oxford Semi 952 rev B workaround
     */
    if (up->bugs & UART_BUG_QUOT && (quot & 0xff) == 0)
        quot++;

    return quot;
}

static unsigned int serial8250_get_divisor(struct uart_port *port,
                                           unsigned int baud,
                                           unsigned int *frac)
{
    if (port->get_divisor)
        return port->get_divisor(port, baud, frac);

    return serial8250_do_get_divisor(port, baud, frac);
}

void serial8250_rpm_get(struct uart_8250_port *p)
{
    if (!(p->capabilities & UART_CAP_RPM))
        return;
    //pm_runtime_get_sync(p->port.dev);
}
EXPORT_SYMBOL_GPL(serial8250_rpm_get);

void
serial8250_do_set_termios(struct uart_port *port,
                          struct ktermios *termios,
                          struct ktermios *old)
{
    struct uart_8250_port *up = up_to_u8250p(port);
    unsigned char cval;
    unsigned long flags;
    unsigned int baud, quot, frac = 0;

    if (up->capabilities & UART_CAP_MINI) {
        termios->c_cflag &= ~(CSTOPB | PARENB | PARODD | CMSPAR);
        if ((termios->c_cflag & CSIZE) == CS5 ||
            (termios->c_cflag & CSIZE) == CS6)
            termios->c_cflag = (termios->c_cflag & ~CSIZE) | CS7;
    }
    cval = serial8250_compute_lcr(up, termios->c_cflag);

    baud = serial8250_get_baud_rate(port, termios, old);
    quot = serial8250_get_divisor(port, baud, &frac);

    /*
     * Ok, we're now changing the port state.  Do it with
     * interrupts disabled.
     */
    serial8250_rpm_get(up);
    spin_lock_irqsave(&port->lock, flags);

    up->lcr = cval;                 /* Save computed LCR */

    if (up->capabilities & UART_CAP_FIFO && port->fifosize > 1) {
        /* NOTE: If fifo_bug is not set, a user can set RX_trigger. */
        if ((baud < 2400 && !up->dma) || up->fifo_bug) {
            up->fcr &= ~UART_FCR_TRIGGER_MASK;
            up->fcr |= UART_FCR_TRIGGER_1;
        }
    }

    /*
     * MCR-based auto flow control.  When AFE is enabled, RTS will be
     * deasserted when the receive FIFO contains more characters than
     * the trigger, or the MCR RTS bit is cleared.
     */
    if (up->capabilities & UART_CAP_AFE) {
        up->mcr &= ~UART_MCR_AFE;
        if (termios->c_cflag & CRTSCTS)
            up->mcr |= UART_MCR_AFE;
    }

#if 0
    /*
     * Update the per-port timeout.
     */
    uart_update_timeout(port, termios->c_cflag, baud);

    port->read_status_mask = UART_LSR_OE | UART_LSR_THRE | UART_LSR_DR;
    if (termios->c_iflag & INPCK)
        port->read_status_mask |= UART_LSR_FE | UART_LSR_PE;
    if (termios->c_iflag & (IGNBRK | BRKINT | PARMRK))
        port->read_status_mask |= UART_LSR_BI;

    /*
     * Characteres to ignore
     */
    port->ignore_status_mask = 0;
    if (termios->c_iflag & IGNPAR)
        port->ignore_status_mask |= UART_LSR_PE | UART_LSR_FE;
    if (termios->c_iflag & IGNBRK) {
        port->ignore_status_mask |= UART_LSR_BI;
        /*
         * If we're ignoring parity and break indicators,
         * ignore overruns too (for real raw support).
         */
        if (termios->c_iflag & IGNPAR)
            port->ignore_status_mask |= UART_LSR_OE;
    }

    /*
     * ignore all characters if CREAD is not set
     */
    if ((termios->c_cflag & CREAD) == 0)
        port->ignore_status_mask |= UART_LSR_DR;
#endif

    panic("%s: END!\n", __func__);
}

static void
serial8250_set_termios(struct uart_port *port, struct ktermios *termios,
                       struct ktermios *old)
{
    if (port->set_termios)
        port->set_termios(port, termios, old);
    else
        serial8250_do_set_termios(port, termios, old);
}

static void
serial8250_set_ldisc(struct uart_port *port, struct ktermios *termios)
{
    panic("%s: END!\n", __func__);
}

static const char *serial8250_type(struct uart_port *port)
{
    int type = port->type;

    if (type >= ARRAY_SIZE(uart_config))
        type = 0;
    return uart_config[type].name;
}

static void serial8250_release_port(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

static int serial8250_request_port(struct uart_port *port)
{
    panic("%s: END!\n", __func__);
}

/*
 * This routine is called by rs_init() to initialize a specific serial
 * port.  It determines what type of UART chip this serial port is
 * using: 8250, 16450, 16550, 16550A.  The important question is
 * whether or not this UART is a 16550A or not, since this will
 * determine whether or not we can use its FIFO features or not.
 */
static void autoconfig(struct uart_8250_port *up)
{
    panic("%s: END!\n", __func__);
}

static void autoconfig_irq(struct uart_8250_port *up)
{
    panic("%s: END!\n", __func__);
}

static void serial8250_release_std_resource(struct uart_8250_port *up)
{
    panic("%s: END!\n", __func__);
}

static void register_dev_spec_attr_grp(struct uart_8250_port *up)
{
    const struct serial8250_config *conf_type =
        &uart_config[up->port.type];

#if 0
    if (conf_type->rxtrig_bytes[0])
        up->port.attr_group = &serial8250_dev_attr_group;
#endif
}

static void serial8250_config_port(struct uart_port *port, int flags)
{
    struct uart_8250_port *up = up_to_u8250p(port);
    int ret;

    /*
     * Find the region that we can probe for.  This in turn
     * tells us whether we can probe for the type of port.
     */
    ret = serial8250_request_std_resource(up);
    if (ret < 0)
        return;

    if (port->iotype != up->cur_iotype)
        set_io_from_upio(port);

    if (flags & UART_CONFIG_TYPE)
        autoconfig(up);

    if (port->rs485.flags & SER_RS485_ENABLED)
        port->rs485_config(port, &port->rs485);

    /* if access method is AU, it is a 16550 with a quirk */
    if (port->type == PORT_16550A && port->iotype == UPIO_AU)
        up->bugs |= UART_BUG_NOMSR;

    /* HW bugs may trigger IRQ while IIR == NO_INT */
    if (port->type == PORT_TEGRA)
        up->bugs |= UART_BUG_NOMSR;

    if (port->type != PORT_UNKNOWN && flags & UART_CONFIG_IRQ)
        autoconfig_irq(up);

    if (port->type == PORT_UNKNOWN)
        serial8250_release_std_resource(up);

    register_dev_spec_attr_grp(up);
    up->fcr = uart_config[up->port.type].fcr;
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

static unsigned int mem_serial_in(struct uart_port *p, int offset)
{
    offset = offset << p->regshift;
    return readb(p->membase + offset);
}

static void mem_serial_out(struct uart_port *p, int offset, int value)
{
    offset = offset << p->regshift;
    writeb(value, p->membase + offset);
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
        p->serial_in = mem_serial_in;
        p->serial_out = mem_serial_out;
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
        unsigned int type = up->port.type;

        if (!up->port.fifosize)
            up->port.fifosize = uart_config[type].fifo_size;
        if (!up->tx_loadsz)
            up->tx_loadsz = uart_config[type].tx_loadsz;
        if (!up->capabilities)
            up->capabilities = uart_config[type].flags;
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

static unsigned int probe_baud(struct uart_port *port)
{
    unsigned char lcr, dll, dlm;
    unsigned int quot;

    lcr = serial_port_in(port, UART_LCR);
    serial_port_out(port, UART_LCR, lcr | UART_LCR_DLAB);
    dll = serial_port_in(port, UART_DLL);
    dlm = serial_port_in(port, UART_DLM);
    serial_port_out(port, UART_LCR, lcr);

    quot = (dlm << 8) | dll;
    return (port->uartclk / 16) / quot;
}

int serial8250_console_setup(struct uart_port *port, char *options,
                             bool probe)
{
    int baud = 9600;
    int bits = 8;
    int parity = 'n';
    int flow = 'n';
    int ret;

    if (!port->iobase && !port->membase)
        return -ENODEV;

    if (options)
        uart_parse_options(options, &baud, &parity, &bits, &flow);
    else if (probe)
        baud = probe_baud(port);

    ret = uart_set_options(port, port->cons, baud, parity, bits, flow);
    if (ret)
        return ret;

#if 0
    if (port->dev)
        pm_runtime_get_sync(port->dev);
#endif

    return 0;
}

void serial8250_init_port(struct uart_8250_port *up)
{
    struct uart_port *port = &up->port;

    spin_lock_init(&port->lock);
    port->ops = &serial8250_pops;
    port->has_sysrq = 1;

    up->cur_iotype = 0xFF;
}
EXPORT_SYMBOL_GPL(serial8250_init_port);

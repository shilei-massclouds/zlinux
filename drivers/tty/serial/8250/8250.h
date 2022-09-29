/* SPDX-License-Identifier: GPL-2.0+ */
/*
 *  Driver for 8250/16550-type serial ports
 *
 *  Based on drivers/char/serial.c, by Linus Torvalds, Theodore Ts'o.
 *
 *  Copyright (C) 2001 Russell King.
 */

#include <linux/bits.h>
#include <linux/serial_8250.h>
#include <linux/serial_reg.h>
#include <linux/dmaengine.h>

#include "../serial_mctrl_gpio.h"

#define UART_CAP_FIFO   BIT(8)  /* UART has FIFO */
#define UART_CAP_EFR    BIT(9)  /* UART has EFR */
#define UART_CAP_SLEEP  BIT(10) /* UART has IER sleep */
#define UART_CAP_AFE    BIT(11) /* MCR-based hw flow control */
#define UART_CAP_UUE    BIT(12) /* UART needs IER bit 6 set (Xscale) */
#define UART_CAP_RTOIE  BIT(13) /* UART needs IER bit 4 set (Xscale, Tegra) */
#define UART_CAP_HFIFO  BIT(14) /* UART has a "hidden" FIFO */
#define UART_CAP_RPM    BIT(15) /* Runtime PM is active while idle */
#define UART_CAP_IRDA   BIT(16) /* UART supports IrDA line discipline */
#define UART_CAP_MINI   BIT(17) /* Mini UART on BCM283X family lacks:
                                 * STOP PARITY EPAR SPAR WLEN5 WLEN6
                                 */

#define UART_BUG_QUOT   BIT(0)  /* UART has buggy quot LSB */
#define UART_BUG_TXEN   BIT(1)  /* UART has buggy TX IIR status */
#define UART_BUG_NOMSR  BIT(2)  /* UART has buggy MSR status bits (Au1x00) */
#define UART_BUG_THRE   BIT(3)  /* UART has buggy THRE reassertion */
#define UART_BUG_PARITY BIT(4)  /* UART mishandles parity if FIFO enabled */
#define UART_BUG_TXRACE BIT(5)  /* UART Tx fails to set remote DR */

#define SERIAL8250_SHARE_IRQS 0

int serial8250_em485_config(struct uart_port *port, struct serial_rs485 *rs485);
void serial8250_em485_start_tx(struct uart_8250_port *p);
void serial8250_em485_stop_tx(struct uart_8250_port *p);
void serial8250_em485_destroy(struct uart_8250_port *p);

static inline int serial_in(struct uart_8250_port *up, int offset)
{
    return up->port.serial_in(&up->port, offset);
}

static inline
void serial_out(struct uart_8250_port *up, int offset, int value)
{
    up->port.serial_out(&up->port, offset, value);
}

struct uart_8250_dma {
    int (*tx_dma)(struct uart_8250_port *p);
    int (*rx_dma)(struct uart_8250_port *p);

    /* Filter function */
    dma_filter_fn       fn;
    /* Parameter to the filter function */
    void            *rx_param;
    void            *tx_param;

    struct dma_slave_config rxconf;
    struct dma_slave_config txconf;

    struct dma_chan     *rxchan;
    struct dma_chan     *txchan;

    /* Device address base for DMA operations */
    phys_addr_t     rx_dma_addr;
    phys_addr_t     tx_dma_addr;

    /* DMA address of the buffer in memory */
    dma_addr_t      rx_addr;
    dma_addr_t      tx_addr;

    dma_cookie_t        rx_cookie;
    dma_cookie_t        tx_cookie;

    void            *rx_buf;

    size_t          rx_size;
    size_t          tx_size;

    unsigned char       tx_running;
    unsigned char       tx_err;
    unsigned char       rx_running;
};

struct old_serial_port {
    unsigned int uart;
    unsigned int baud_base;
    unsigned int port;
    unsigned int irq;
    upf_t        flags;
    unsigned char io_type;
    unsigned char __iomem *iomem_base;
    unsigned short iomem_reg_shift;
};

struct serial8250_config {
    const char  *name;
    unsigned short  fifo_size;
    unsigned short  tx_loadsz;
    unsigned char   fcr;
    unsigned char   rxtrig_bytes[UART_FCR_R_TRIG_MAX_STATE];
    unsigned int    flags;
};

static inline int serial8250_pnp_init(void) { return 0; }
static inline void serial8250_pnp_exit(void) { }

/* MCR <-> TIOCM conversion */
static inline int serial8250_TIOCM_to_MCR(int tiocm)
{
    int mcr = 0;

    if (tiocm & TIOCM_RTS)
        mcr |= UART_MCR_RTS;
    if (tiocm & TIOCM_DTR)
        mcr |= UART_MCR_DTR;
    if (tiocm & TIOCM_OUT1)
        mcr |= UART_MCR_OUT1;
    if (tiocm & TIOCM_OUT2)
        mcr |= UART_MCR_OUT2;
    if (tiocm & TIOCM_LOOP)
        mcr |= UART_MCR_LOOP;

    return mcr;
}

static inline
void serial8250_out_MCR(struct uart_8250_port *up, int value)
{
    serial_out(up, UART_MCR, value);

#if 0
    if (up->gpios)
        mctrl_gpio_set(up->gpios, serial8250_MCR_to_TIOCM(value));
#endif
}

static inline void serial_dl_write(struct uart_8250_port *up, int value)
{
    up->dl_write(up, value);
}

static inline bool serial8250_set_THRI(struct uart_8250_port *up)
{
    if (up->ier & UART_IER_THRI)
        return false;
    up->ier |= UART_IER_THRI;
    serial_out(up, UART_IER, up->ier);
    return true;
}

static inline bool serial8250_clear_THRI(struct uart_8250_port *up)
{
    if (!(up->ier & UART_IER_THRI))
        return false;
    up->ier &= ~UART_IER_THRI;
    serial_out(up, UART_IER, up->ier);
    return true;
}

static inline int serial8250_tx_dma(struct uart_8250_port *p)
{
    return -1;
}
static inline int serial8250_rx_dma(struct uart_8250_port *p)
{
    return -1;
}
static inline void serial8250_rx_dma_flush(struct uart_8250_port *p) { }
static inline int serial8250_request_dma(struct uart_8250_port *p)
{
    return -1;
}
static inline void serial8250_release_dma(struct uart_8250_port *p) { }

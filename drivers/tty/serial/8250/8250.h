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
//#include <linux/serial_reg.h>
//#include <linux/dmaengine.h>

//#include "../serial_mctrl_gpio.h"

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

static inline int serial8250_pnp_init(void) { return 0; }
static inline void serial8250_pnp_exit(void) { }

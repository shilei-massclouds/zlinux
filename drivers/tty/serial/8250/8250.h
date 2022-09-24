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

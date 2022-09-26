/* SPDX-License-Identifier: GPL-1.0+ WITH Linux-syscall-note */
/*
 * include/linux/serial_reg.h
 *
 * Copyright (C) 1992, 1994 by Theodore Ts'o.
 *
 * Redistribution of this file is permitted under the terms of the GNU
 * Public License (GPL)
 *
 * These are the UART port assignments, expressed as offsets from the base
 * register.  These assignments should hold for any serial port based on
 * a 8250, 16450, or 16550(A).
 */

#ifndef _LINUX_SERIAL_REG_H
#define _LINUX_SERIAL_REG_H

/*
 * DLAB=1
 */
#define UART_DLL        0       /* Out: Divisor Latch Low */
#define UART_DLM        1       /* Out: Divisor Latch High */
#define UART_DIV_MAX    0xFFFF  /* Max divisor value */

#define UART_IIR    2   /* In:  Interrupt ID Register */
#define UART_IIR_NO_INT     0x01 /* No interrupts pending */
#define UART_IIR_ID     0x0e /* Mask for the interrupt ID */
#define UART_IIR_MSI        0x00 /* Modem status interrupt */
#define UART_IIR_THRI       0x02 /* Transmitter holding register empty */
#define UART_IIR_RDI        0x04 /* Receiver data interrupt */
#define UART_IIR_RLSI       0x06 /* Receiver line status interrupt */

#define UART_IIR_BUSY       0x07 /* DesignWare APB Busy Detect */

#define UART_IIR_RX_TIMEOUT 0x0c /* OMAP RX Timeout interrupt */
#define UART_IIR_XOFF       0x10 /* OMAP XOFF/Special Character */
#define UART_IIR_CTS_RTS_DSR    0x20 /* OMAP CTS/RTS/DSR Change */

#define UART_FCR    2   /* Out: FIFO Control Register */
#define UART_FCR_ENABLE_FIFO    0x01 /* Enable the FIFO */
#define UART_FCR_CLEAR_RCVR 0x02 /* Clear the RCVR FIFO */
#define UART_FCR_CLEAR_XMIT 0x04 /* Clear the XMIT FIFO */
#define UART_FCR_DMA_SELECT 0x08 /* For DMA applications */

/*
 * Note: The FIFO trigger levels are chip specific:
 *  RX:76 = 00  01  10  11  TX:54 = 00  01  10  11
 * PC16550D:     1   4   8  14      xx  xx  xx  xx
 * TI16C550A:    1   4   8  14          xx  xx  xx  xx
 * TI16C550C:    1   4   8  14          xx  xx  xx  xx
 * ST16C550:     1   4   8  14      xx  xx  xx  xx
 * ST16C650:     8  16  24  28      16   8  24  30  PORT_16650V2
 * NS16C552:     1   4   8  14      xx  xx  xx  xx
 * ST16C654:     8  16  56  60       8  16  32  56  PORT_16654
 * TI16C750:     1  16  32  56      xx  xx  xx  xx  PORT_16750
 * TI16C752:     8  16  56  60       8  16  32  56
 * OX16C950:    16  32 112 120      16  32  64 112  PORT_16C950
 * Tegra:    1   4   8  14      16   8   4   1  PORT_TEGRA
 */
#define UART_FCR_R_TRIG_00  0x00
#define UART_FCR_R_TRIG_01  0x40
#define UART_FCR_R_TRIG_10  0x80
#define UART_FCR_R_TRIG_11  0xc0
#define UART_FCR_T_TRIG_00  0x00
#define UART_FCR_T_TRIG_01  0x10
#define UART_FCR_T_TRIG_10  0x20
#define UART_FCR_T_TRIG_11  0x30

#define UART_FCR_TRIGGER_MASK   0xC0 /* Mask for the FIFO trigger range */
#define UART_FCR_TRIGGER_1  0x00 /* Mask for trigger set at 1 */
#define UART_FCR_TRIGGER_4  0x40 /* Mask for trigger set at 4 */
#define UART_FCR_TRIGGER_8  0x80 /* Mask for trigger set at 8 */
#define UART_FCR_TRIGGER_14 0xC0 /* Mask for trigger set at 14 */
/* 16650 definitions */
#define UART_FCR6_R_TRIGGER_8   0x00 /* Mask for receive trigger set at 1 */
#define UART_FCR6_R_TRIGGER_16  0x40 /* Mask for receive trigger set at 4 */
#define UART_FCR6_R_TRIGGER_24  0x80 /* Mask for receive trigger set at 8 */
#define UART_FCR6_R_TRIGGER_28  0xC0 /* Mask for receive trigger set at 14 */
#define UART_FCR6_T_TRIGGER_16  0x00 /* Mask for transmit trigger set at 16 */
#define UART_FCR6_T_TRIGGER_8   0x10 /* Mask for transmit trigger set at 8 */
#define UART_FCR6_T_TRIGGER_24  0x20 /* Mask for transmit trigger set at 24 */
#define UART_FCR6_T_TRIGGER_30  0x30 /* Mask for transmit trigger set at 30 */
#define UART_FCR7_64BYTE    0x20 /* Go into 64 byte mode (TI16C750 and
                    some Freescale UARTs) */

#define UART_FCR_R_TRIG_SHIFT       6
#define UART_FCR_R_TRIG_BITS(x)     \
    (((x) & UART_FCR_TRIGGER_MASK) >> UART_FCR_R_TRIG_SHIFT)
#define UART_FCR_R_TRIG_MAX_STATE   4

#define UART_MCR    4   /* Out: Modem Control Register */
#define UART_MCR_CLKSEL     0x80 /* Divide clock by 4 (TI16C752, EFR[4]=1) */
#define UART_MCR_TCRTLR     0x40 /* Access TCR/TLR (TI16C752, EFR[4]=1) */
#define UART_MCR_XONANY     0x20 /* Enable Xon Any (TI16C752, EFR[4]=1) */
#define UART_MCR_AFE        0x20 /* Enable auto-RTS/CTS (TI16C550C/TI16C750) */
#define UART_MCR_LOOP       0x10 /* Enable loopback test mode */
#define UART_MCR_OUT2       0x08 /* Out2 complement */
#define UART_MCR_OUT1       0x04 /* Out1 complement */
#define UART_MCR_RTS        0x02 /* RTS complement */
#define UART_MCR_DTR        0x01 /* DTR complement */

#define UART_LCR    3   /* Out: Line Control Register */
/*
 * Note: if the word length is 5 bits (UART_LCR_WLEN5), then setting
 * UART_LCR_STOP will select 1.5 stop bits, not 2 stop bits.
 */
#define UART_LCR_DLAB       0x80 /* Divisor latch access bit */
#define UART_LCR_SBC        0x40 /* Set break control */
#define UART_LCR_SPAR       0x20 /* Stick parity (?) */
#define UART_LCR_EPAR       0x10 /* Even parity select */
#define UART_LCR_PARITY     0x08 /* Parity Enable */
#define UART_LCR_STOP       0x04 /* Stop bits: 0=1 bit, 1=2 bits */
#define UART_LCR_WLEN5      0x00 /* Wordlength: 5 bits */
#define UART_LCR_WLEN6      0x01 /* Wordlength: 6 bits */
#define UART_LCR_WLEN7      0x02 /* Wordlength: 7 bits */
#define UART_LCR_WLEN8      0x03 /* Wordlength: 8 bits */

#endif /* _LINUX_SERIAL_REG_H */

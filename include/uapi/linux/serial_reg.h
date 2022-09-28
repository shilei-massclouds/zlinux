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
 * DLAB=0
 */
#define UART_RX     0   /* In:  Receive buffer */
#define UART_TX     0   /* Out: Transmit buffer */

/*
 * DLAB=1
 */
#define UART_DLL        0       /* Out: Divisor Latch Low */
#define UART_DLM        1       /* Out: Divisor Latch High */
#define UART_DIV_MAX    0xFFFF  /* Max divisor value */

#define UART_IER    1   /* Out: Interrupt Enable Register */
#define UART_IER_MSI        0x08 /* Enable Modem status interrupt */
#define UART_IER_RLSI       0x04 /* Enable receiver line status interrupt */
#define UART_IER_THRI       0x02 /* Enable Transmitter holding register int. */
#define UART_IER_RDI        0x01 /* Enable receiver data interrupt */
/*
 * Sleep mode for ST16650 and TI16750.  For the ST16650, EFR[4]=1
 */
#define UART_IERX_SLEEP     0x10 /* Enable sleep mode */

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

#define UART_LSR    5   /* In:  Line Status Register */
#define UART_LSR_FIFOE      0x80 /* Fifo error */
#define UART_LSR_TEMT       0x40 /* Transmitter empty */
#define UART_LSR_THRE       0x20 /* Transmit-hold-register empty */
#define UART_LSR_BI     0x10 /* Break interrupt indicator */
#define UART_LSR_FE     0x08 /* Frame error indicator */
#define UART_LSR_PE     0x04 /* Parity error indicator */
#define UART_LSR_OE     0x02 /* Overrun error indicator */
#define UART_LSR_DR     0x01 /* Receiver data ready */
#define UART_LSR_BRK_ERROR_BITS 0x1E /* BI, FE, PE, OE bits */

/*
 * The Intel XScale on-chip UARTs define these bits
 */
#define UART_IER_DMAE   0x80    /* DMA Requests Enable */
#define UART_IER_UUE    0x40    /* UART Unit Enable */
#define UART_IER_NRZE   0x20    /* NRZ coding Enable */
#define UART_IER_RTOIE  0x10    /* Receiver Time Out Interrupt Enable */

/*
 * LCR=0xBF (or DLAB=1 for 16C660)
 */
#define UART_EFR    2   /* I/O: Extended Features Register */
#define UART_XR_EFR 9   /* I/O: Extended Features Register (XR17D15x) */
#define UART_EFR_CTS        0x80 /* CTS flow control */
#define UART_EFR_RTS        0x40 /* RTS flow control */
#define UART_EFR_SCD        0x20 /* Special character detect */
#define UART_EFR_ECB        0x10 /* Enhanced control bit */

/*
 * Access to some registers depends on register access / configuration
 * mode.
 */
#define UART_LCR_CONF_MODE_A    UART_LCR_DLAB   /* Configutation mode A */
#define UART_LCR_CONF_MODE_B    0xBF        /* Configutation mode B */

#define UART_SCR    7   /* I/O: Scratch Register */

#define UART_MSR    6   /* In:  Modem Status Register */
#define UART_MSR_DCD        0x80 /* Data Carrier Detect */
#define UART_MSR_RI     0x40 /* Ring Indicator */
#define UART_MSR_DSR        0x20 /* Data Set Ready */
#define UART_MSR_CTS        0x10 /* Clear to Send */
#define UART_MSR_DDCD       0x08 /* Delta DCD */
#define UART_MSR_TERI       0x04 /* Trailing edge ring indicator */
#define UART_MSR_DDSR       0x02 /* Delta DSR */
#define UART_MSR_DCTS       0x01 /* Delta CTS */
#define UART_MSR_ANY_DELTA  0x0F /* Any of the delta bits! */

/*
 * These register definitions are for the 16C950
 */
#define UART_ASR    0x01    /* Additional Status Register */
#define UART_RFL    0x03    /* Receiver FIFO level */
#define UART_TFL    0x04    /* Transmitter FIFO level */
#define UART_ICR    0x05    /* Index Control Register */

/* The 16950 ICR registers */
#define UART_ACR    0x00    /* Additional Control Register */
#define UART_CPR    0x01    /* Clock Prescalar Register */
#define UART_TCR    0x02    /* Times Clock Register */
#define UART_CKS    0x03    /* Clock Select Register */
#define UART_TTL    0x04    /* Transmitter Interrupt Trigger Level */
#define UART_RTL    0x05    /* Receiver Interrupt Trigger Level */
#define UART_FCL    0x06    /* Flow Control Level Lower */
#define UART_FCH    0x07    /* Flow Control Level Higher */
#define UART_ID1    0x08    /* ID #1 */
#define UART_ID2    0x09    /* ID #2 */
#define UART_ID3    0x0A    /* ID #3 */
#define UART_REV    0x0B    /* Revision */
#define UART_CSR    0x0C    /* Channel Software Reset */
#define UART_NMR    0x0D    /* Nine-bit Mode Register */
#define UART_CTR    0xFF

#endif /* _LINUX_SERIAL_REG_H */

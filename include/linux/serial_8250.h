/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  linux/include/linux/serial_8250.h
 *
 *  Copyright (C) 2004 Russell King
 */
#ifndef _LINUX_SERIAL_8250_H
#define _LINUX_SERIAL_8250_H

#include <linux/serial_core.h>
//#include <linux/serial_reg.h>
#include <linux/platform_device.h>

/*
 * This should be used by drivers which want to register
 * their own 8250 ports without registering their own
 * platform device.  Using these will make your driver
 * dependent on the 8250 driver.
 */
struct uart_8250_port {
    struct uart_port    port;
    struct timer_list   timer;      /* "no irq" timer */
    struct list_head    list;       /* ports on this IRQ */
    u32         capabilities;   /* port capabilities */
    unsigned short      bugs;       /* port bugs */
    bool            fifo_bug;   /* min RX trigger if enabled */
    unsigned int        tx_loadsz;  /* transmit fifo load size */
    unsigned char       acr;
    unsigned char       fcr;
    unsigned char       ier;
    unsigned char       lcr;
    unsigned char       mcr;
    unsigned char       cur_iotype; /* Running I/O type */
    unsigned int        rpm_tx_active;
    unsigned char       canary;     /* non-zero during system sleep
                         *   if no_console_suspend
                         */
    unsigned char       probe;
    struct mctrl_gpios  *gpios;
#define UART_PROBE_RSA  (1 << 0)

    /*
     * Some bits in registers are cleared on a read, so they must
     * be saved whenever the register is read but the bits will not
     * be immediately processed.
     */
#define LSR_SAVE_FLAGS UART_LSR_BRK_ERROR_BITS
    unsigned char       lsr_saved_flags;
#define MSR_SAVE_FLAGS UART_MSR_ANY_DELTA
    unsigned char       msr_saved_flags;

    struct uart_8250_dma    *dma;
    const struct uart_8250_ops *ops;

    /* 8250 specific callbacks */
    int         (*dl_read)(struct uart_8250_port *);
    void            (*dl_write)(struct uart_8250_port *, int);

    struct uart_8250_em485 *em485;
    void            (*rs485_start_tx)(struct uart_8250_port *);
    void            (*rs485_stop_tx)(struct uart_8250_port *);

    /* Serial port overrun backoff */
    struct delayed_work overrun_backoff;
    u32 overrun_backoff_time_ms;
};

#endif /* _LINUX_SERIAL_8250_H */

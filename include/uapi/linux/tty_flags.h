/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _LINUX_TTY_FLAGS_H
#define _LINUX_TTY_FLAGS_H

/*
 * Definitions for async_struct (and serial_struct) flags field also
 * shared by the tty_port flags structures.
 *
 * Define ASYNCB_* for convenient use with {test,set,clear}_bit.
 *
 * Bits [0..ASYNCB_LAST_USER] are userspace defined/visible/changeable
 * [x] in the bit comments indicates the flag is defunct and no longer used.
 */
#define ASYNCB_HUP_NOTIFY    0 /* Notify getty on hangups and closes
                    * on the callout port */
#define ASYNCB_FOURPORT      1 /* Set OUT1, OUT2 per AST Fourport settings */
#define ASYNCB_SAK       2 /* Secure Attention Key (Orange book) */
#define ASYNCB_SPLIT_TERMIOS     3 /* [x] Separate termios for dialin/callout */
#define ASYNCB_SPD_HI        4 /* Use 57600 instead of 38400 bps */
#define ASYNCB_SPD_VHI       5 /* Use 115200 instead of 38400 bps */
#define ASYNCB_SKIP_TEST     6 /* Skip UART test during autoconfiguration */
#define ASYNCB_AUTO_IRQ      7 /* Do automatic IRQ during
                    * autoconfiguration */
#define ASYNCB_SESSION_LOCKOUT   8 /* [x] Lock out cua opens based on session */
#define ASYNCB_PGRP_LOCKOUT  9 /* [x] Lock out cua opens based on pgrp */
#define ASYNCB_CALLOUT_NOHUP    10 /* [x] Don't do hangups for cua device */
#define ASYNCB_HARDPPS_CD   11 /* Call hardpps when CD goes high  */
#define ASYNCB_SPD_SHI      12 /* Use 230400 instead of 38400 bps */
#define ASYNCB_LOW_LATENCY  13 /* Request low latency behaviour */
#define ASYNCB_BUGGY_UART   14 /* This is a buggy UART, skip some safety
                    * checks.  Note: can be dangerous! */
#define ASYNCB_AUTOPROBE    15 /* [x] Port was autoprobed by PCI/PNP code */
#define ASYNCB_MAGIC_MULTIPLIER 16 /* Use special CLK or divisor */
#define ASYNCB_LAST_USER    16

/* Masks */
#define ASYNC_HUP_NOTIFY    (1U << ASYNCB_HUP_NOTIFY)
#define ASYNC_SUSPENDED     (1U << ASYNCB_SUSPENDED)
#define ASYNC_FOURPORT      (1U << ASYNCB_FOURPORT)
#define ASYNC_SAK       (1U << ASYNCB_SAK)
#define ASYNC_SPLIT_TERMIOS (1U << ASYNCB_SPLIT_TERMIOS)
#define ASYNC_SPD_HI        (1U << ASYNCB_SPD_HI)
#define ASYNC_SPD_VHI       (1U << ASYNCB_SPD_VHI)
#define ASYNC_SKIP_TEST     (1U << ASYNCB_SKIP_TEST)
#define ASYNC_AUTO_IRQ      (1U << ASYNCB_AUTO_IRQ)
#define ASYNC_SESSION_LOCKOUT   (1U << ASYNCB_SESSION_LOCKOUT)
#define ASYNC_PGRP_LOCKOUT  (1U << ASYNCB_PGRP_LOCKOUT)
#define ASYNC_CALLOUT_NOHUP (1U << ASYNCB_CALLOUT_NOHUP)
#define ASYNC_HARDPPS_CD    (1U << ASYNCB_HARDPPS_CD)
#define ASYNC_SPD_SHI       (1U << ASYNCB_SPD_SHI)
#define ASYNC_LOW_LATENCY   (1U << ASYNCB_LOW_LATENCY)
#define ASYNC_BUGGY_UART    (1U << ASYNCB_BUGGY_UART)
#define ASYNC_AUTOPROBE     (1U << ASYNCB_AUTOPROBE)
#define ASYNC_MAGIC_MULTIPLIER  (1U << ASYNCB_MAGIC_MULTIPLIER)

#define ASYNC_FLAGS     ((1U << (ASYNCB_LAST_USER + 1)) - 1)
#define ASYNC_DEPRECATED    (ASYNC_SPLIT_TERMIOS | ASYNC_SESSION_LOCKOUT | \
        ASYNC_PGRP_LOCKOUT | ASYNC_CALLOUT_NOHUP | ASYNC_AUTOPROBE)
#define ASYNC_USR_MASK      (ASYNC_SPD_MASK|ASYNC_CALLOUT_NOHUP| \
        ASYNC_LOW_LATENCY)
#define ASYNC_SPD_CUST      (ASYNC_SPD_HI|ASYNC_SPD_VHI)
#define ASYNC_SPD_WARP      (ASYNC_SPD_HI|ASYNC_SPD_SHI)
#define ASYNC_SPD_MASK      (ASYNC_SPD_HI|ASYNC_SPD_VHI|ASYNC_SPD_SHI)

#endif /* _LINUX_TTY_FLAGS_H */

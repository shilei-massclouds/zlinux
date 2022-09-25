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

#endif /* _LINUX_SERIAL_REG_H */

/* SPDX-License-Identifier: GPL-1.0+ WITH Linux-syscall-note */
/*
 * include/linux/serial.h
 *
 * Copyright (C) 1992 by Theodore Ts'o.
 *
 * Redistribution of this file is permitted under the terms of the GNU
 * Public License (GPL)
 */

#ifndef _UAPI_LINUX_SERIAL_H
#define _UAPI_LINUX_SERIAL_H

#include <linux/types.h>

//#include <linux/tty_flags.h>

/*
 * For the close wait times, 0 means wait forever for serial port to
 * flush its output.  65535 means don't wait at all.
 */
#define ASYNC_CLOSING_WAIT_INF  0
#define ASYNC_CLOSING_WAIT_NONE 65535

/*
 * These are the supported serial types.
 */
#define PORT_UNKNOWN    0
#define PORT_8250   1
#define PORT_16450  2
#define PORT_16550  3
#define PORT_16550A 4
#define PORT_CIRRUS     5
#define PORT_16650  6
#define PORT_16650V2    7
#define PORT_16750  8
#define PORT_STARTECH   9
#define PORT_16C950 10  /* Oxford Semiconductor */
#define PORT_16654  11
#define PORT_16850  12
#define PORT_RSA    13  /* RSA-DV II/S card */
#define PORT_MAX    13

#endif /* _UAPI_LINUX_SERIAL_H */

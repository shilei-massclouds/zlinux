/*
 * include/linux/serial.h
 *
 * Copyright (C) 1992 by Theodore Ts'o.
 *
 * Redistribution of this file is permitted under the terms of the GNU
 * Public License (GPL)
 */
#ifndef _LINUX_SERIAL_H
#define _LINUX_SERIAL_H

#include <asm/page.h>
#include <uapi/linux/serial.h>

/* Helper for dealing with UART_LCR_WLEN* defines */
#define UART_LCR_WLEN(x)    ((x) - 5)

#include <linux/compiler.h>

#endif /* _LINUX_SERIAL_H */

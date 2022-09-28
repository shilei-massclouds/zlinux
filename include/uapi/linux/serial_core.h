/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 *  linux/drivers/char/serial_core.h
 *
 *  Copyright (C) 2000 Deep Blue Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef _UAPILINUX_SERIAL_CORE_H
#define _UAPILINUX_SERIAL_CORE_H

#include <linux/serial.h>

/*
 * The type definitions.  These are from Ted Ts'o's serial.h
 */
#define PORT_NS16550A   14
#define PORT_XSCALE 15
#define PORT_RM9000 16  /* PMC-Sierra RM9xxx internal UART */
#define PORT_OCTEON 17  /* Cavium OCTEON internal UART */
#define PORT_AR7    18  /* Texas Instruments AR7 internal UART */
#define PORT_U6_16550A  19  /* ST-Ericsson U6xxx internal UART */
#define PORT_TEGRA  20  /* NVIDIA Tegra internal UART */
#define PORT_XR17D15X   21  /* Exar XR17D15x UART */
#define PORT_LPC3220    22  /* NXP LPC32xx SoC "Standard" UART */
#define PORT_8250_CIR   23  /* CIR infrared port, has its own driver */
#define PORT_XR17V35X   24  /* Exar XR17V35x UARTs */
#define PORT_BRCM_TRUMANAGE 25
#define PORT_ALTR_16550_F32 26  /* Altera 16550 UART with 32 FIFOs */
#define PORT_ALTR_16550_F64 27  /* Altera 16550 UART with 64 FIFOs */
#define PORT_ALTR_16550_F128 28 /* Altera 16550 UART with 128 FIFOs */
#define PORT_RT2880 29  /* Ralink RT2880 internal UART */
#define PORT_16550A_FSL64 30    /* Freescale 16550 UART with 64 FIFOs */

/* Nuvoton UART */
#define PORT_NPCM   40

/* TI DA8xx/66AK2x */
#define PORT_DA830  95

#endif /* _UAPILINUX_SERIAL_CORE_H */

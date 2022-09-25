/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * {read,write}{b,w,l,q} based on arch/arm64/include/asm/io.h
 *   which was based on arch/arm/include/io.h
 *
 * Copyright (C) 1996-2000 Russell King
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2014 Regents of the University of California
 */

#ifndef _ASM_RISCV_IO_H
#define _ASM_RISCV_IO_H

#include <linux/types.h>
#include <linux/pgtable.h>
#include <asm/mmiowb.h>
#include <asm/early_ioremap.h>

/*
 * MMIO access functions are separated out to break dependency cycles
 * when using {read,write}* fns in low-level headers
 */
#include <asm/mmio.h>

/*
 *  I/O port access constants.
 */
#define IO_SPACE_LIMIT  (PCI_IO_SIZE - 1)
#define PCI_IOBASE      ((void __iomem *)PCI_IO_START)

/*
 * Emulation routines for the port-mapped IO space used by some PCI drivers.
 * These are defined as being "fully synchronous", but also "not guaranteed to
 * be fully ordered with respect to other memory and I/O operations".  We're
 * going to be on the safe side here and just make them:
 *  - Fully ordered WRT each other, by bracketing them with two fences.  The
 *    outer set contains both I/O so inX is ordered with outX, while the inner just
 *    needs the type of the access (I for inX and O for outX).
 *  - Ordered in the same manner as readX/writeX WRT memory by subsuming their
 *    fences.
 *  - Ordered WRT timer reads, so udelay and friends don't get elided by the
 *    implementation.
 * Note that there is no way to actually enforce that outX is a non-posted
 * operation on RISC-V, but hopefully the timer ordering constraint is
 * sufficient to ensure this works sanely on controllers that support I/O
 * writes.
 */
#define __io_pbr()  __asm__ __volatile__ ("fence io,i"  : : : "memory");
#define __io_par(v) __asm__ __volatile__ ("fence i,ior" : : : "memory");
#define __io_pbw()  __asm__ __volatile__ ("fence iow,o" : : : "memory");
#define __io_paw()  __asm__ __volatile__ ("fence o,io"  : : : "memory");

#include <asm-generic/io.h>

#endif /* _ASM_RISCV_IO_H */

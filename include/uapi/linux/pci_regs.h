/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 *  PCI standard defines
 *  Copyright 1994, Drew Eckhardt
 *  Copyright 1997--1999 Martin Mares <mj@ucw.cz>
 *
 *  For more information, please consult the following manuals (look at
 *  http://www.pcisig.com/ for how to get them):
 *
 *  PCI BIOS Specification
 *  PCI Local Bus Specification
 *  PCI to PCI Bridge Specification
 *  PCI System Design Guide
 *
 *  For HyperTransport information, please consult the following manuals
 *  from http://www.hypertransport.org :
 *
 *  The HyperTransport I/O Link Specification
 */

#ifndef LINUX_PCI_REGS_H
#define LINUX_PCI_REGS_H

/*
 * Base addresses specify locations in memory or I/O space.
 * Decoded size can be determined by writing a value of
 * 0xffffffff to the register, and reading it back.  Only
 * 1 bits are decoded.
 */
#define PCI_BASE_ADDRESS_0  0x10    /* 32 bits */
#define PCI_BASE_ADDRESS_1  0x14    /* 32 bits [htype 0,1 only] */
#define PCI_BASE_ADDRESS_2  0x18    /* 32 bits [htype 0 only] */
#define PCI_BASE_ADDRESS_3  0x1c    /* 32 bits */
#define PCI_BASE_ADDRESS_4  0x20    /* 32 bits */
#define PCI_BASE_ADDRESS_5  0x24    /* 32 bits */
#define  PCI_BASE_ADDRESS_SPACE     0x01    /* 0 = memory, 1 = I/O */
#define  PCI_BASE_ADDRESS_SPACE_IO  0x01
#define  PCI_BASE_ADDRESS_SPACE_MEMORY  0x00
#define  PCI_BASE_ADDRESS_MEM_TYPE_MASK 0x06
#define  PCI_BASE_ADDRESS_MEM_TYPE_32   0x00    /* 32 bit address */
#define  PCI_BASE_ADDRESS_MEM_TYPE_1M   0x02    /* Below 1M [obsolete] */
#define  PCI_BASE_ADDRESS_MEM_TYPE_64   0x04    /* 64 bit address */
#define  PCI_BASE_ADDRESS_MEM_PREFETCH  0x08    /* prefetchable? */
#define  PCI_BASE_ADDRESS_MEM_MASK  (~0x0fUL)
#define  PCI_BASE_ADDRESS_IO_MASK   (~0x03UL)
/* bit 1 is reserved if address_space = 1 */

#endif /* LINUX_PCI_REGS_H */

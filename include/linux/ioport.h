/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ioport.h Definitions of routines for detecting, reserving and
 *      allocating system resources.
 *
 * Authors: Linus Torvalds
 */

#ifndef _LINUX_IOPORT_H
#define _LINUX_IOPORT_H

#ifndef __ASSEMBLY__
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/bits.h>
/*
 * Resources are tree-like, allowing
 * nesting etc..
 */
struct resource {
    resource_size_t start;
    resource_size_t end;
    const char *name;
    unsigned long flags;
    unsigned long desc;
    struct resource *parent, *sibling, *child;
};

#define IORESOURCE_TYPE_BITS    0x00001f00  /* Resource type */

#define IORESOURCE_IO       0x00000100  /* PCI/ISA I/O ports */
#define IORESOURCE_MEM      0x00000200
#define IORESOURCE_REG      0x00000300  /* Register offsets */
#define IORESOURCE_IRQ      0x00000400
#define IORESOURCE_DMA      0x00000800
#define IORESOURCE_BUS      0x00001000

#define IORESOURCE_PREFETCH     0x00002000  /* No side effects */
#define IORESOURCE_READONLY     0x00004000
#define IORESOURCE_CACHEABLE    0x00008000
#define IORESOURCE_RANGELENGTH  0x00010000
#define IORESOURCE_SHADOWABLE   0x00020000

#define IORESOURCE_MEM_64   0x00100000
#define IORESOURCE_WINDOW   0x00200000  /* forwarded by bridge */
#define IORESOURCE_MUXED    0x00400000  /* Resource is software muxed */

#define IORESOURCE_DISABLED 0x10000000
#define IORESOURCE_UNSET    0x20000000  /* No address assigned yet */
#define IORESOURCE_AUTO     0x40000000
#define IORESOURCE_BUSY     0x80000000  /* Driver has marked this resource busy */

static inline resource_size_t resource_size(const struct resource *res)
{
    return res->end - res->start + 1;
}

#endif /* __ASSEMBLY__ */
#endif  /* _LINUX_IOPORT_H */

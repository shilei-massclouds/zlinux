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

#define IORESOURCE_EXT_TYPE_BITS 0x01000000 /* Resource extended types */
#define IORESOURCE_SYSRAM   0x01000000  /* System RAM (modifier) */

#define IORESOURCE_DISABLED 0x10000000
#define IORESOURCE_UNSET    0x20000000  /* No address assigned yet */
#define IORESOURCE_AUTO     0x40000000
#define IORESOURCE_BUSY     0x80000000  /* Driver has marked this resource busy */

/* PnP memory I/O specific bits (IORESOURCE_BITS) */
#define IORESOURCE_MEM_WRITEABLE    (1<<0)  /* dup: IORESOURCE_READONLY */
#define IORESOURCE_MEM_CACHEABLE    (1<<1)  /* dup: IORESOURCE_CACHEABLE */
#define IORESOURCE_MEM_RANGELENGTH  (1<<2)  /* dup: IORESOURCE_RANGELENGTH */
#define IORESOURCE_MEM_TYPE_MASK    (3<<3)
#define IORESOURCE_MEM_8BIT         (0<<3)
#define IORESOURCE_MEM_16BIT        (1<<3)
#define IORESOURCE_MEM_8AND16BIT    (2<<3)
#define IORESOURCE_MEM_32BIT        (3<<3)
#define IORESOURCE_MEM_SHADOWABLE   (1<<5)  /* dup: IORESOURCE_SHADOWABLE */
#define IORESOURCE_MEM_EXPANSIONROM (1<<6)
#define IORESOURCE_MEM_NONPOSTED    (1<<7)

extern struct resource iomem_resource;

static inline resource_size_t resource_size(const struct resource *res)
{
    return res->end - res->start + 1;
}

static inline unsigned long resource_type(const struct resource *res)
{
    return res->flags & IORESOURCE_TYPE_BITS;
}

static inline unsigned long resource_ext_type(const struct resource *res)
{
    return res->flags & IORESOURCE_EXT_TYPE_BITS;
}

#define devm_request_region(dev,start,n,name) \
    __devm_request_region(dev, &ioport_resource, (start), (n), (name))
#define devm_request_mem_region(dev,start,n,name) \
    __devm_request_region(dev, &iomem_resource, (start), (n), (name))

#define devm_release_region(dev, start, n) \
    __devm_release_region(dev, &ioport_resource, (start), (n))
#define devm_release_mem_region(dev, start, n) \
    __devm_release_region(dev, &iomem_resource, (start), (n))

/* Wrappers for managed devices */
struct device;

extern void __devm_release_region(struct device *dev, struct resource *parent,
                                  resource_size_t start, resource_size_t n);

extern struct resource *
__devm_request_region(struct device *dev,
                      struct resource *parent, resource_size_t start,
                      resource_size_t n, const char *name);

#endif /* __ASSEMBLY__ */
#endif  /* _LINUX_IOPORT_H */

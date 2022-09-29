/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Generic I/O port emulation.
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
#ifndef __ASM_GENERIC_IO_H
#define __ASM_GENERIC_IO_H

#include <asm/page.h> /* I/O is all done through memory accesses */
#include <linux/string.h> /* for memset() and memcpy() */
#include <linux/types.h>

#ifdef CONFIG_GENERIC_IOMAP
#include <asm-generic/iomap.h>
#endif

#include <asm/mmiowb.h>
//#include <asm-generic/pci_iomap.h>

#ifndef ioread8
#define ioread8 ioread8
static inline u8 ioread8(const volatile void __iomem *addr)
{
    return readb(addr);
}
#endif

#ifndef ioread16
#define ioread16 ioread16
static inline u16 ioread16(const volatile void __iomem *addr)
{
    return readw(addr);
}
#endif

#ifndef ioread32
#define ioread32 ioread32
static inline u32 ioread32(const volatile void __iomem *addr)
{
    return readl(addr);
}
#endif

#ifndef ioread64
#define ioread64 ioread64
static inline u64 ioread64(const volatile void __iomem *addr)
{
    return readq(addr);
}
#endif

#ifdef __KERNEL__

/*
 * Change virtual addresses to physical addresses and vv.
 * These are pretty trivial
 */
#ifndef virt_to_phys
#define virt_to_phys virt_to_phys
static inline unsigned long virt_to_phys(volatile void *address)
{
    return __pa((unsigned long)address);
}
#endif

#ifndef phys_to_virt
#define phys_to_virt phys_to_virt
static inline void *phys_to_virt(unsigned long address)
{
    return __va(address);
}
#endif

/*
 * ioremap_np needs an explicit architecture implementation, as it
 * requests stronger semantics than regular ioremap(). Portable drivers
 * should instead use one of the higher-level abstractions, like
 * devm_ioremap_resource(), to choose the correct variant for any given
 * device and bus. Portable drivers with a good reason to want non-posted
 * write semantics should always provide an ioremap() fallback in case
 * ioremap_np() is not available.
 */
#ifndef ioremap_np
#define ioremap_np ioremap_np
static inline void __iomem *ioremap_np(phys_addr_t offset, size_t size)
{
    return NULL;
}
#endif

#include <linux/pgtable.h>

void __iomem *ioremap_prot(phys_addr_t addr, size_t size, unsigned long prot);
void iounmap(volatile void __iomem *addr);

static inline void __iomem *ioremap(phys_addr_t addr, size_t size)
{
    /* _PAGE_IOREMAP needs to be supplied by the architecture */
    return ioremap_prot(addr, size, _PAGE_IOREMAP);
}

/*
 * {in,out}{b,w,l}() access little endian I/O. {in,out}{b,w,l}_p() can be
 * implemented on hardware that needs an additional delay for I/O accesses to
 * take effect.
 */

#if !defined(inb) && !defined(_inb)
#define _inb _inb
static inline u8 _inb(unsigned long addr)
{
    u8 val;

    __io_pbr();
    val = __raw_readb(PCI_IOBASE + addr);
    __io_par(val);
    return val;
}
#endif

#if !defined(inw) && !defined(_inw)
#define _inw _inw
static inline u16 _inw(unsigned long addr)
{
    u16 val;

    __io_pbr();
    val = __le16_to_cpu((__le16 __force)__raw_readw(PCI_IOBASE + addr));
    __io_par(val);
    return val;
}
#endif

#if !defined(inl) && !defined(_inl)
#define _inl _inl
static inline u32 _inl(unsigned long addr)
{
    u32 val;

    __io_pbr();
    val = __le32_to_cpu((__le32 __force)__raw_readl(PCI_IOBASE + addr));
    __io_par(val);
    return val;
}
#endif

#if !defined(outb) && !defined(_outb)
#define _outb _outb
static inline void _outb(u8 value, unsigned long addr)
{
    __io_pbw();
    __raw_writeb(value, PCI_IOBASE + addr);
    __io_paw();
}
#endif

#if !defined(outw) && !defined(_outw)
#define _outw _outw
static inline void _outw(u16 value, unsigned long addr)
{
    __io_pbw();
    __raw_writew((u16 __force)cpu_to_le16(value), PCI_IOBASE + addr);
    __io_paw();
}
#endif

#if !defined(outl) && !defined(_outl)
#define _outl _outl
static inline void _outl(u32 value, unsigned long addr)
{
    __io_pbw();
    __raw_writel((u32 __force)cpu_to_le32(value), PCI_IOBASE + addr);
    __io_paw();
}
#endif

#ifndef inb
#define inb _inb
#endif

#ifndef inw
#define inw _inw
#endif

#ifndef inl
#define inl _inl
#endif

#ifndef outb
#define outb _outb
#endif

#ifndef outw
#define outw _outw
#endif

#ifndef outl
#define outl _outl
#endif

#ifndef inb_p
#define inb_p inb_p
static inline u8 inb_p(unsigned long addr)
{
    return inb(addr);
}
#endif

#ifndef inw_p
#define inw_p inw_p
static inline u16 inw_p(unsigned long addr)
{
    return inw(addr);
}
#endif

#ifndef inl_p
#define inl_p inl_p
static inline u32 inl_p(unsigned long addr)
{
    return inl(addr);
}
#endif

#ifndef outb_p
#define outb_p outb_p
static inline void outb_p(u8 value, unsigned long addr)
{
    outb(value, addr);
}
#endif

#ifndef outw_p
#define outw_p outw_p
static inline void outw_p(u16 value, unsigned long addr)
{
    outw(value, addr);
}
#endif

#ifndef outl_p
#define outl_p outl_p
static inline void outl_p(u32 value, unsigned long addr)
{
    outl(value, addr);
}
#endif

#endif /* __KERNEL__ */

#endif /* __ASM_GENERIC_IO_H */

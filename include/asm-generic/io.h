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

#endif /* __KERNEL__ */

#endif /* __ASM_GENERIC_IO_H */

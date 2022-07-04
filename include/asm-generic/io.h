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

#ifdef __KERNEL__

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

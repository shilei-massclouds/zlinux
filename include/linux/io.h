/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2006 PathScale, Inc.  All Rights Reserved.
 */

#ifndef _LINUX_IO_H
#define _LINUX_IO_H

#include <linux/types.h>
#include <linux/init.h>
#include <linux/bug.h>
#include <linux/err.h>
#include <asm/io.h>
#include <asm/page.h>

struct device;
struct resource;

int ioremap_page_range(unsigned long addr, unsigned long end,
                       phys_addr_t phys_addr, pgprot_t prot);

#define IOMEM_ERR_PTR(err) (__force void __iomem *)ERR_PTR(err)

#endif /* _LINUX_IO_H */

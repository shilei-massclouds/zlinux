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

/* Content */

#include <asm-generic/io.h>

#endif /* _ASM_RISCV_IO_H */

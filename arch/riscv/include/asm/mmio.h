/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * {read,write}{b,w,l,q} based on arch/arm64/include/asm/io.h
 *   which was based on arch/arm/include/io.h
 *
 * Copyright (C) 1996-2000 Russell King
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2014 Regents of the University of California
 */

#ifndef _ASM_RISCV_MMIO_H
#define _ASM_RISCV_MMIO_H

#include <linux/types.h>
#include <asm/mmiowb.h>

/* Generic IO read/write.  These perform native-endian accesses. */
#define __raw_writeb __raw_writeb
static inline void __raw_writeb(u8 val, volatile void __iomem *addr)
{
    asm volatile("sb %0, 0(%1)" : : "r" (val), "r" (addr));
}

#define __raw_writew __raw_writew
static inline void __raw_writew(u16 val, volatile void __iomem *addr)
{
    asm volatile("sh %0, 0(%1)" : : "r" (val), "r" (addr));
}

#define __raw_writel __raw_writel
static inline void __raw_writel(u32 val, volatile void __iomem *addr)
{
    asm volatile("sw %0, 0(%1)" : : "r" (val), "r" (addr));
}

#define __raw_readb __raw_readb
static inline u8 __raw_readb(const volatile void __iomem *addr)
{
    u8 val;

    asm volatile("lb %0, 0(%1)" : "=r" (val) : "r" (addr));
    return val;
}

#define __raw_readw __raw_readw
static inline u16 __raw_readw(const volatile void __iomem *addr)
{
    u16 val;

    asm volatile("lh %0, 0(%1)" : "=r" (val) : "r" (addr));
    return val;
}

#define __raw_readl __raw_readl
static inline u32 __raw_readl(const volatile void __iomem *addr)
{
    u32 val;

    asm volatile("lw %0, 0(%1)" : "=r" (val) : "r" (addr));
    return val;
}

/*
 * Unordered I/O memory access primitives.  These are even more relaxed than
 * the relaxed versions, as they don't even order accesses between successive
 * operations to the I/O regions.
 */
#define readb_cpu(c) \
    ({ u8  __r = __raw_readb(c); __r; })
#define readw_cpu(c) \
    ({ u16 __r = le16_to_cpu((__force __le16)__raw_readw(c)); __r; })
#define readl_cpu(c) \
    ({ u32 __r = le32_to_cpu((__force __le32)__raw_readl(c)); __r; })

#define writeb_cpu(v, c) \
    ((void)__raw_writeb((v), (c)))
#define writew_cpu(v, c) \
    ((void)__raw_writew((__force u16)cpu_to_le16(v), (c)))
#define writel_cpu(v, c) \
    ((void)__raw_writel((__force u32)cpu_to_le32(v), (c)))

/*
 * I/O memory access primitives. Reads are ordered relative to any
 * following Normal memory access. Writes are ordered relative to any prior
 * Normal memory access.  The memory barriers here are necessary as RISC-V
 * doesn't define any ordering between the memory space and the I/O space.
 */
#define __io_br()   do {} while (0)
#define __io_ar(v)  __asm__ __volatile__ ("fence i,r" : : : "memory")
#define __io_bw()   __asm__ __volatile__ ("fence w,o" : : : "memory")
#define __io_aw()   mmiowb_set_pending()

#define readb(c) \
    ({ u8  __v; __io_br(); __v = readb_cpu(c); __io_ar(__v); __v; })
#define readw(c) \
    ({ u16 __v; __io_br(); __v = readw_cpu(c); __io_ar(__v); __v; })
#define readl(c) \
    ({ u32 __v; __io_br(); __v = readl_cpu(c); __io_ar(__v); __v; })

#define writeb(v, c) \
    ({ __io_bw(); writeb_cpu((v), (c)); __io_aw(); })
#define writew(v, c) \
    ({ __io_bw(); writew_cpu((v), (c)); __io_aw(); })
#define writel(v, c) \
    ({ __io_bw(); writel_cpu((v), (c)); __io_aw(); })

#endif /* _ASM_RISCV_MMIO_H */

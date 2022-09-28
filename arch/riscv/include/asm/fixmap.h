/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_FIXMAP_H
#define _ASM_RISCV_FIXMAP_H

#include <linux/sizes.h>

/*
 * Here we define all the compile-time 'special' virtual addresses.
 * The point is to have a constant address at compile time, but to
 * set the physical address only in the boot process.
 *
 * These 'compile-time allocated' memory buffers are page-sized. Use
 * set_fixmap(idx,phys) to associate physical memory with fixmap indices.
 */
enum fixed_addresses {
    FIX_HOLE,
    FIX_PTE,
    FIX_PMD,
    FIX_PUD,
    FIX_P4D,
    FIX_TEXT_POKE1,
    FIX_TEXT_POKE0,
    FIX_EARLYCON_MEM_BASE,

    __end_of_permanent_fixed_addresses,
    /*
     * Temporary boot-time mappings, used by early_ioremap(),
     * before ioremap() is functional.
     */
#define NR_FIX_BTMAPS       (SZ_256K / PAGE_SIZE)
#define FIX_BTMAPS_SLOTS    7
#define TOTAL_FIX_BTMAPS    (NR_FIX_BTMAPS * FIX_BTMAPS_SLOTS)

    FIX_BTMAP_END = __end_of_permanent_fixed_addresses,
    FIX_BTMAP_BEGIN = FIX_BTMAP_END + TOTAL_FIX_BTMAPS - 1,

    __end_of_fixed_addresses
};

#define FIXMAP_PAGE_IO      PAGE_KERNEL

extern void __set_fixmap(enum fixed_addresses idx,
                         phys_addr_t phys, pgprot_t prot);

#include <asm-generic/fixmap.h>

#endif /* _ASM_RISCV_FIXMAP_H */

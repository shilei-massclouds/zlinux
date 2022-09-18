/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copied from arch/arm64/include/asm/hwcap.h
 *
 * Copyright (C) 2012 ARM Ltd.
 * Copyright (C) 2017 SiFive
 */
#ifndef _ASM_RISCV_HWCAP_H
#define _ASM_RISCV_HWCAP_H

#include <linux/bits.h>
#include <uapi/asm/hwcap.h>

#ifndef __ASSEMBLY__
/*
 * This yields a mask that user programs can use to figure out what
 * instruction set this cpu supports.
 */
#define ELF_HWCAP       (elf_hwcap)

enum {
    CAP_HWCAP = 1,
};

extern unsigned long elf_hwcap;

/*
 * Increse this to higher value as kernel support more ISA extensions.
 */
#define RISCV_ISA_EXT_MAX   64
#define RISCV_ISA_EXT_NAME_LEN_MAX 32

/* The base ID for multi-letter ISA extensions */
#define RISCV_ISA_EXT_BASE 26

/*
 * This enum represent the logical ID for each multi-letter RISC-V ISA extension.
 * The logical ID should start from RISCV_ISA_EXT_BASE and must not exceed
 * RISCV_ISA_EXT_MAX. 0-25 range is reserved for single letter
 * extensions while all the multi-letter extensions should define the next
 * available logical extension id.
 */
enum riscv_isa_ext_id {
    RISCV_ISA_EXT_SSCOFPMF = RISCV_ISA_EXT_BASE,
    RISCV_ISA_EXT_ID_MAX = RISCV_ISA_EXT_MAX,
};

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_HWCAP_H */

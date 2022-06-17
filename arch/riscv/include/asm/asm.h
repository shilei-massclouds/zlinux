/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 Regents of the University of California
 */

#ifndef _ASM_RISCV_ASM_H
#define _ASM_RISCV_ASM_H

#ifdef __ASSEMBLY__
#define __ASM_STR(x)    x
#else
#define __ASM_STR(x)    #x
#endif

#define REG_L   __ASM_STR(ld)
#define REG_S   __ASM_STR(sd)
#define REG_SC  __ASM_STR(sc.d)
#define SZREG   __ASM_STR(8)
#define LGREG   __ASM_STR(3)

#ifdef __ASSEMBLY__
#define RISCV_PTR       .dword
#define RISCV_SZPTR     8
#define RISCV_LGPTR     3
#else
#define RISCV_PTR       ".dword"
#define RISCV_SZPTR     "8"
#define RISCV_LGPTR     "3"
#endif

#if (__SIZEOF_INT__ == 4)
#define RISCV_INT       __ASM_STR(.word)
#define RISCV_SZINT     __ASM_STR(4)
#define RISCV_LGINT     __ASM_STR(2)
#else
#error "Unexpected __SIZEOF_INT__"
#endif

#if (__SIZEOF_SHORT__ == 2)
#define RISCV_SHORT     __ASM_STR(.half)
#define RISCV_SZSHORT   __ASM_STR(2)
#define RISCV_LGSHORT   __ASM_STR(1)
#else
#error "Unexpected __SIZEOF_SHORT__"
#endif

#endif /* _ASM_RISCV_ASM_H */

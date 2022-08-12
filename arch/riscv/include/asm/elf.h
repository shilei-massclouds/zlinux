/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2003 Matjaz Breskvar <phoenix@bsemi.com>
 * Copyright (C) 2010-2011 Jonas Bonn <jonas@southpole.se>
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_ELF_H
#define _ASM_RISCV_ELF_H

//#include <uapi/asm/elf.h>
//#include <asm/auxvec.h>
#include <asm/byteorder.h>
//#include <asm/cacheinfo.h>

/*
 * These are used to set parameters in the core dumps.
 */
#define ELF_ARCH    EM_RISCV

#define ELF_CLASS   ELFCLASS64

#define ELF_DATA    ELFDATA2LSB

/*
 * This is used to ensure we don't load something for the wrong architecture.
 */
#define elf_check_arch(x) ((x)->e_machine == EM_RISCV)

#define CORE_DUMP_USE_REGSET
#define ELF_EXEC_PAGESIZE   (PAGE_SIZE)

#endif /* _ASM_RISCV_ELF_H */

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

#define ARCH_DLINFO                     \
do {                                \
    NEW_AUX_ENT(AT_SYSINFO_EHDR,                \
        (elf_addr_t)current->mm->context.vdso);     \
    NEW_AUX_ENT(AT_L1I_CACHESIZE,               \
        get_cache_size(1, CACHE_TYPE_INST));        \
    NEW_AUX_ENT(AT_L1I_CACHEGEOMETRY,           \
        get_cache_geometry(1, CACHE_TYPE_INST));    \
    NEW_AUX_ENT(AT_L1D_CACHESIZE,               \
        get_cache_size(1, CACHE_TYPE_DATA));        \
    NEW_AUX_ENT(AT_L1D_CACHEGEOMETRY,           \
        get_cache_geometry(1, CACHE_TYPE_DATA));    \
    NEW_AUX_ENT(AT_L2_CACHESIZE,                \
        get_cache_size(2, CACHE_TYPE_UNIFIED));     \
    NEW_AUX_ENT(AT_L2_CACHEGEOMETRY,            \
        get_cache_geometry(2, CACHE_TYPE_UNIFIED)); \
} while (0)
#define ARCH_HAS_SETUP_ADDITIONAL_PAGES
struct linux_binprm;
extern int arch_setup_additional_pages(struct linux_binprm *bprm,
                                       int uses_interp);

/*
 * This yields a string that ld.so will use to load implementation
 * specific libraries for optimization.  This is more specific in
 * intent than poking at uname or /proc/cpuinfo.
 */
#define ELF_PLATFORM    (NULL)

#endif /* _ASM_RISCV_ELF_H */
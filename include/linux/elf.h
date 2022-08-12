/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ELF_H
#define _LINUX_ELF_H

#include <linux/types.h>
#include <asm/elf.h>
#include <uapi/linux/elf.h>

#define ELF64_GNU_PROPERTY_ALIGN    8

extern Elf64_Dyn _DYNAMIC [];
#define elfhdr      elf64_hdr
#define elf_phdr    elf64_phdr
#define elf_shdr    elf64_shdr
#define elf_note    elf64_note
#define elf_addr_t  Elf64_Off
#define Elf_Half    Elf64_Half
#define Elf_Word    Elf64_Word
#define ELF_GNU_PROPERTY_ALIGN  ELF64_GNU_PROPERTY_ALIGN

#endif /* _LINUX_ELF_H */

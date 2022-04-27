/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_ELF_H
#define _UAPI_LINUX_ELF_H

#include <linux/types.h>
//#include <linux/elf-em.h>

/* 32-bit ELF base types. */
typedef __u32   Elf32_Addr;
typedef __u16   Elf32_Half;
typedef __u32   Elf32_Off;
typedef __s32   Elf32_Sword;
typedef __u32   Elf32_Word;

/* 64-bit ELF base types. */
typedef __u64   Elf64_Addr;
typedef __u16   Elf64_Half;
typedef __s16   Elf64_SHalf;
typedef __u64   Elf64_Off;
typedef __s32   Elf64_Sword;
typedef __u32   Elf64_Word;
typedef __u64   Elf64_Xword;
typedef __s64   Elf64_Sxword;

/* Note header in a PT_NOTE section */
typedef struct elf32_note {
  Elf32_Word    n_namesz;   /* Name size */
  Elf32_Word    n_descsz;   /* Content size */
  Elf32_Word    n_type;     /* Content type */
} Elf32_Nhdr;

/* Note header in a PT_NOTE section */
typedef struct elf64_note {
  Elf64_Word n_namesz;  /* Name size */
  Elf64_Word n_descsz;  /* Content size */
  Elf64_Word n_type;    /* Content type */
} Elf64_Nhdr;

#endif /* _UAPI_LINUX_ELF_H */

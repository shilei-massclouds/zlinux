/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ELF_H
#define _LINUX_ELF_H

#include <linux/types.h>
#include <asm/elf.h>
#include <uapi/linux/elf.h>

#ifndef elf_read_implies_exec
  /* Executables for which elf_read_implies_exec() returns TRUE will
     have the READ_IMPLIES_EXEC personality flag set automatically.
     Override in asm/elf.h as needed.  */
# define elf_read_implies_exec(ex, have_pt_gnu_stack)   0
#endif

#ifndef SET_PERSONALITY
#define SET_PERSONALITY(ex) \
    set_personality(PER_LINUX | (current->personality & (~PER_MASK)))
#endif

#ifndef SET_PERSONALITY2
#define SET_PERSONALITY2(ex, state) \
    SET_PERSONALITY(ex)
#endif

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

static inline int arch_elf_adjust_prot(int prot,
                                       const struct arch_elf_state *state,
                                       bool has_interp, bool is_interp)
{
    return prot;
}

#if defined(ARCH_HAS_SETUP_ADDITIONAL_PAGES) && !defined(ARCH_SETUP_ADDITIONAL_PAGES)
#define ARCH_SETUP_ADDITIONAL_PAGES(bprm, ex, interpreter) \
    arch_setup_additional_pages(bprm, interpreter)
#endif

#ifndef START_THREAD
#define START_THREAD(elf_ex, regs, elf_entry, start_stack)  \
    start_thread(regs, elf_entry, start_stack)
#endif

#endif /* _LINUX_ELF_H */

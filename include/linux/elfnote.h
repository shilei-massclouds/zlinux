/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ELFNOTE_H
#define _LINUX_ELFNOTE_H

#ifdef __ASSEMBLER__
/*
 * Generate a structure with the same shape as Elf{32,64}_Nhdr (which
 * turn out to be the same size and shape), followed by the name and
 * desc data with appropriate padding.  The 'desctype' argument is the
 * assembler pseudo op defining the type of the data e.g. .asciz while
 * 'descdata' is the data itself e.g.  "hello, world".
 *
 * e.g. ELFNOTE(XYZCo, 42, .asciz, "forty-two")
 *      ELFNOTE(XYZCo, 12, .long, 0xdeadbeef)
 */
#define ELFNOTE_START(name, type, flags)    \
.pushsection .note.name, flags,@note    ;   \
  .balign 4             ;   \
  .long 2f - 1f     /* namesz */    ;   \
  .long 4484f - 3f  /* descsz */    ;   \
  .long type                ;   \
1:.asciz #name              ;   \
2:.balign 4             ;   \
3:

#define ELFNOTE_END             \
4484:.balign 4              ;   \
.popsection             ;

#define ELFNOTE(name, type, desc)   \
    ELFNOTE_START(name, type, "a")  \
        desc            ;           \
    ELFNOTE_END

#else   /* !__ASSEMBLER__ */
#include <uapi/linux/elf.h>

#define _ELFNOTE_PASTE(a,b) a##b
#define _ELFNOTE(size, name, unique, type, desc)    \
    static const struct {                           \
        struct elf##size##_note _nhdr;              \
        unsigned char _name[sizeof(name)]           \
        __attribute__((aligned(sizeof(Elf##size##_Word)))); \
        typeof(desc) _desc                          \
                 __attribute__((aligned(sizeof(Elf##size##_Word)))); \
    } _ELFNOTE_PASTE(_note_, unique)                \
        __used                                      \
        __attribute__((section(".note." name),          \
                   aligned(sizeof(Elf##size##_Word)),   \
                   unused)) = { \
        {                       \
            sizeof(name),       \
            sizeof(desc),       \
            type,               \
        },                      \
        name,                   \
        desc                    \
    }

#define ELFNOTE(size, name, type, desc) \
    _ELFNOTE(size, name, __LINE__, type, desc)

#define ELFNOTE32(name, type, desc) ELFNOTE(32, name, type, desc)
#define ELFNOTE64(name, type, desc) ELFNOTE(64, name, type, desc)

#endif  /* __ASSEMBLER__ */

#endif /* _LINUX_ELFNOTE_H */

/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_ASM_EXTABLE_H
#define __ASM_ASM_EXTABLE_H

#define EX_TYPE_NONE                0
#define EX_TYPE_FIXUP               1
#define EX_TYPE_BPF                 2
#define EX_TYPE_UACCESS_ERR_ZERO    3

#ifdef __ASSEMBLY__

#define __ASM_EXTABLE_RAW(insn, fixup, type, data)  \
    .pushsection    __ex_table, "a";                \
    .balign     4;                                  \
    .long       ((insn) - .);                       \
    .long       ((fixup) - .);                      \
    .short      (type);                             \
    .short      (data);                             \
    .popsection;

.macro  _asm_extable, insn, fixup
__ASM_EXTABLE_RAW(\insn, \fixup, EX_TYPE_FIXUP, 0)
.endm

#else /* __ASSEMBLY__ */

#endif /* __ASSEMBLY__ */

#endif /* __ASM_ASM_EXTABLE_H */

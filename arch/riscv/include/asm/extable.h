/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_EXTABLE_H
#define _ASM_RISCV_EXTABLE_H

#define ARCH_HAS_RELATIVE_EXTABLE

/*
 * The exception table consists of pairs of relative offsets: the first
 * is the relative offset to an instruction that is allowed to fault,
 * and the second is the relative offset at which the program should
 * continue. No registers are modified, so it is entirely up to the
 * continuation code to figure out what to do.
 *
 * All the routines below use bits of fixup code that are out of line
 * with the main instruction path.  This means when everything is well,
 * we don't even have to jump over them.  Further, they do not intrude
 * on our cache or tlb entries.
 */

struct exception_table_entry {
    int insn, fixup;
    short type, data;
};

bool fixup_exception(struct pt_regs *regs);

static inline
bool ex_handler_bpf(const struct exception_table_entry *ex,
                    struct pt_regs *regs)
{
    return false;
}

#endif /* _ASM_RISCV_EXTABLE_H */

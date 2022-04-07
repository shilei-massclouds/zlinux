/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_BUG_H
#define _ASM_RISCV_BUG_H

#include <asm/asm.h>

#define __BUG_ENTRY_ADDR    RISCV_INT " 1b - 2b"
#define __BUG_ENTRY_FILE    RISCV_INT " %0 - 2b"

#define __BUG_ENTRY             \
    __BUG_ENTRY_ADDR "\n\t"     \
    __BUG_ENTRY_FILE "\n\t"     \
    RISCV_SHORT " %1\n\t"       \
    RISCV_SHORT " %2"

#define __BUG_FLAGS(flags)  \
do {                        \
    __asm__ __volatile__ (  \
        "1:\n\t"                    \
            "ebreak\n"              \
            ".pushsection __bug_table,\"aw\"\n\t"   \
        "2:\n\t"                    \
            __BUG_ENTRY "\n\t"          \
            ".org 2b + %3\n\t"                      \
            ".popsection"               \
        :                       \
        : "i" (__FILE__), "i" (__LINE__),       \
          "i" (flags),                  \
          "i" (sizeof(struct bug_entry)));              \
} while (0)

#define BUG() do {  \
    __BUG_FLAGS(0); \
    unreachable();  \
} while (0)

#define HAVE_ARCH_BUG

#include <asm-generic/bug.h>

#endif /* _ASM_RISCV_BUG_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LINKAGE_H
#define _LINUX_LINKAGE_H

#include <linux/compiler_types.h>
#include <linux/stringify.h>
#include <linux/export.h>
#include <asm/linkage.h>

/* Some toolchains use other characters (e.g. '`')
 * to mark new line in macro */
#ifndef ASM_NL
#define ASM_NL       ;
#endif

#ifdef __cplusplus
#define CPP_ASMLINKAGE extern "C"
#else
#define CPP_ASMLINKAGE
#endif

#ifndef asmlinkage
#define asmlinkage CPP_ASMLINKAGE
#endif

#define __page_aligned_data \
    __section(.data..page_aligned) __aligned(PAGE_SIZE)

#define __page_aligned_bss \
    __section(.bss..page_aligned) __aligned(PAGE_SIZE)

#ifdef __ASSEMBLY__

#define ALIGN __ALIGN
#define ALIGN_STR __ALIGN_STR

/* SYM_L_* -- linkage of symbols */
#define SYM_L_GLOBAL(name)  .globl name
#define SYM_L_WEAK(name)    .weak name

/* SYM_A_* -- align the symbol? */
#define SYM_A_ALIGN	ALIGN

#ifndef ENTRY
/* deprecated, use SYM_FUNC_START */
#define ENTRY(name) SYM_FUNC_START(name)
#endif

/* SYM_FUNC_START -- use for global functions */
#ifndef SYM_FUNC_START
/*
 * The same as SYM_FUNC_START_ALIAS,
 * but we will need to distinguish these two later.
 */
#define SYM_FUNC_START(name) SYM_START(name, SYM_L_GLOBAL, SYM_A_ALIGN)
#endif

/* SYM_START -- use only if you have to */
#ifndef SYM_START
#define SYM_START(name, linkage, align...) \
    SYM_ENTRY(name, linkage, align)
#endif

/* SYM_ENTRY -- use only if you have to for non-paired symbols */
#ifndef SYM_ENTRY
#define SYM_ENTRY(name, linkage, align...) \
    linkage(name) ASM_NL    \
    align ASM_NL            \
    name:
#endif

/* SYM_FUNC_START_WEAK -- use for weak functions */
#ifndef SYM_FUNC_START_WEAK
#define SYM_FUNC_START_WEAK(name)   \
    SYM_START(name, SYM_L_WEAK, SYM_A_ALIGN)
#endif

#ifndef WEAK
/* deprecated, use SYM_FUNC_START_WEAK* */
#define WEAK(name)     \
    SYM_FUNC_START_WEAK(name)
#endif

#ifndef END
/* deprecated, use SYM_FUNC_END, SYM_DATA_END, or SYM_END */
#define END(name) .size name, .-name
#endif

#endif /* __ASSEMBLY__ */

#endif /* _LINUX_LINKAGE_H */

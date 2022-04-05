/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LINKAGE_H
#define _LINUX_LINKAGE_H

#include <asm/linkage.h>

/* Some toolchains use other characters (e.g. '`')
 * to mark new line in macro */
#ifndef ASM_NL
#define ASM_NL       ;
#endif

#define ALIGN __ALIGN
#define ALIGN_STR __ALIGN_STR

/* SYM_L_* -- linkage of symbols */
#define SYM_L_GLOBAL(name) .globl name

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

#endif /* _LINUX_LINKAGE_H */

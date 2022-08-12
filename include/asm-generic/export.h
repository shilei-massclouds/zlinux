/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_GENERIC_EXPORT_H
#define __ASM_GENERIC_EXPORT_H

#ifndef KSYM_FUNC
#define KSYM_FUNC(x) x
#endif

#define KSYM_ALIGN  8

#ifndef KCRC_ALIGN
#define KCRC_ALIGN 4
#endif

.macro __put, val, name
    .quad   \val, \name, 0
.endm

/*
 * note on .section use: we specify progbits since usage of the "M" (SHF_MERGE)
 * section flag requires it. Use '%progbits' instead of '@progbits' since the
 * former apparently works on all arches according to the binutils source.
 */

.macro ___EXPORT_SYMBOL name,val,sec
    .section ___ksymtab\sec+\name,"a"
    .balign KSYM_ALIGN
__ksymtab_\name:
    __put \val, __kstrtab_\name
    .previous
    .section __ksymtab_strings,"aMS",%progbits,1
__kstrtab_\name:
    .asciz "\name"
    .previous
.endm

#define __EXPORT_SYMBOL(sym, val, sec) ___EXPORT_SYMBOL sym, val, sec

#define EXPORT_SYMBOL(name) \
    __EXPORT_SYMBOL(name, KSYM_FUNC(name),)
#define EXPORT_SYMBOL_GPL(name) \
    __EXPORT_SYMBOL(name, KSYM_FUNC(name), _gpl)
#define EXPORT_DATA_SYMBOL(name) \
    __EXPORT_SYMBOL(name, name,)
#define EXPORT_DATA_SYMBOL_GPL(name) \
    __EXPORT_SYMBOL(name, name,_gpl)

#endif /* __ASM_GENERIC_EXPORT_H */

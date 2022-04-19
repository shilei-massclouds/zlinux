/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EXPORT_H
#define _LINUX_EXPORT_H

#ifndef __ASSEMBLY__

#define __KSYMTAB_ENTRY(sym, sec)                   \
    static const struct kernel_symbol __ksymtab_##sym       \
    __attribute__((section("___ksymtab" sec "+" #sym), used))   \
    __aligned(sizeof(void *))                   \
    = { (unsigned long)&sym, __kstrtab_##sym, __kstrtabns_##sym }

struct kernel_symbol {
    unsigned long value;
    const char *name;
    const char *namespace;
};

/*
 * For every exported symbol, do the following:
 *
 * - If applicable, place a CRC entry in the __kcrctab section.
 * - Put the name of the symbol and namespace (empty string "" for none)
 * in __ksymtab_strings.
 * - Place a struct kernel_symbol entry in the __ksymtab section.
 *
 * note on .section use: we specify progbits since usage of
 * the "M" (SHF_MERGE) section flag requires it.
 * Use '%progbits' instead of '@progbits' since the former
 * apparently works on all arches according to the binutils source.
 */
#define ___EXPORT_SYMBOL(sym, sec, ns)                      \
    extern typeof(sym) sym;                         \
    extern const char __kstrtab_##sym[];                    \
    extern const char __kstrtabns_##sym[];                  \
    asm("   .section \"__ksymtab_strings\",\"aMS\",%progbits,1  \n" \
        "__kstrtab_" #sym ":                    \n" \
        "   .asciz  \"" #sym "\"                \n" \
        "__kstrtabns_" #sym ":                  \n" \
        "   .asciz  \"" ns "\"                  \n" \
        "   .previous                           \n"); \
    __KSYMTAB_ENTRY(sym, sec)

#define __EXPORT_SYMBOL(sym, sec, ns) ___EXPORT_SYMBOL(sym, sec, ns)
#define _EXPORT_SYMBOL(sym, sec) __EXPORT_SYMBOL(sym, sec, "")
#define EXPORT_SYMBOL(sym) _EXPORT_SYMBOL(sym, "")

#define EXPORT_SYMBOL_GPL(sym)  _EXPORT_SYMBOL(sym, "_gpl")

#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_EXPORT_H */

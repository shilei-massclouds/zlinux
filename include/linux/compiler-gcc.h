/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COMPILER_TYPES_H
#error "Please don't include <linux/compiler-gcc.h> directly, include <linux/compiler.h> instead."
#endif

/*
 * Common definitions for all gcc versions go here.
 */
#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 \
                     + __GNUC_PATCHLEVEL__)

#define __compiletime_warning(message) __attribute__((__warning__(message)))
#define __compiletime_error(message) __attribute__((__error__(message)))

/*
 * calling noreturn functions, __builtin_unreachable() and __builtin_trap()
 * confuse the stack allocation in gcc, leading to overly large stack
 * frames, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=82365
 *
 * Adding an empty inline assembly before it works around the problem
 */
#define barrier_before_unreachable() asm volatile("")

/* The "volatile" is due to gcc bugs */
#define barrier() __asm__ __volatile__("": : :"memory")

/*
 * Mark a position in code as unreachable.  This can be used to
 * suppress control flow warnings after asm blocks that transfer
 * control elsewhere.
 */
#define unreachable() \
    do {                                \
        barrier_before_unreachable();   \
        __builtin_unreachable();        \
    } while (0)

#define __no_sanitize_address __attribute__((no_sanitize_address))

#define __no_sanitize_thread

#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __COUNTER__)

#define RELOC_HIDE(ptr, off)                        \
({                                  \
    unsigned long __ptr;                        \
    __asm__ ("" : "=r"(__ptr) : "0"(ptr));              \
    (typeof(ptr)) (__ptr + (off));                  \
})

/*
 * Turn individual warnings and errors on and off locally, depending
 * on version.
 */
#define __diag_GCC(version, severity, s) \
    __diag_GCC_ ## version(__diag_GCC_ ## severity s)

/* Severity used in pragma directives */
#define __diag_GCC_ignore   ignored
#define __diag_GCC_warn     warning
#define __diag_GCC_error    error

#define __diag_str1(s)      #s
#define __diag_str(s)       __diag_str1(s)
#define __diag(s)           _Pragma(__diag_str(GCC diagnostic s))

/*
 * GCC 'asm goto' miscompiles certain code sequences:
 *
 *   http://gcc.gnu.org/bugzilla/show_bug.cgi?id=58670
 *
 * Work it around via a compiler barrier quirk suggested by Jakub Jelinek.
 *
 * (asm goto is automatically volatile - the naming reflects this.)
 */
#define asm_volatile_goto(x...) do { asm goto(x); asm (""); } while (0)

#if GCC_VERSION >= 80000
#define __diag_GCC_8(s)     __diag(s)
#else
#define __diag_GCC_8(s)
#endif

/*
 * Prior to 9.1, -Wno-alloc-size-larger-than (and therefore the "alloc_size"
 * attribute) do not work, and must be disabled.
 */
#if GCC_VERSION < 90100
#undef __alloc_size__
#endif

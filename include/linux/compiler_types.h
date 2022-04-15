/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COMPILER_TYPES_H
#define __LINUX_COMPILER_TYPES_H

#ifndef __ASSEMBLY__

#define __force

/* Indirect macros required for expanded argument pasting, eg. __LINE__. */
#define ___PASTE(a,b) a##b
#define __PASTE(a,b) ___PASTE(a,b)

#ifdef __KERNEL__

/* Attributes */
#include <linux/compiler_attributes.h>

#if defined(__GNUC__)
#include <linux/compiler-gcc.h>
#else
#error "Unknown compiler"
#endif

#define notrace     __attribute__((__no_instrument_function__))
#define __no_kcsan  __no_sanitize_thread

/* Section for code which can't be instrumented at all */
#define noinstr \
    noinline notrace __attribute((__section__(".noinstr.text"))) \
    __no_kcsan __no_sanitize_address

#endif /* __KERNEL__ */

#endif /* __ASSEMBLY__ */

/*
 * The below symbols may be defined for one or more, but not ALL,
 * of the above compilers.
 * We don't consider that to be an error, so set them to nothing.
 * For example, some of them are for compiler specific plugins.
 */
#ifndef __latent_entropy
# define __latent_entropy
#endif

#ifdef __OPTIMIZE__
# define __compiletime_assert(condition, msg, prefix, suffix) \
    do {                                    \
        extern void prefix ## suffix(void) __compiletime_error(msg); \
        if (!(condition))                   \
            prefix ## suffix();             \
    } while (0)
#endif

#define _compiletime_assert(condition, msg, prefix, suffix) \
    __compiletime_assert(condition, msg, prefix, suffix)

/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
#define compiletime_assert(condition, msg) \
    _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)

#define __must_check    __attribute__((__warn_unused_result__))

#endif /* __LINUX_COMPILER_TYPES_H */

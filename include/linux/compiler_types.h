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

/*
 * Rather then using noinline to prevent stack consumption, use
 * noinline_for_stack instead.  For documentation reasons.
 */
#define noinline_for_stack noinline

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

#ifndef __randomize_layout
# define __randomize_layout __designated_init
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

#define compiletime_assert_atomic_type(t)               \
    compiletime_assert(__native_word(t),                \
        "Need native word sized stores/loads for atomicity.")

#define __must_check    __attribute__((__warn_unused_result__))

#define __acquires(x)
#define __releases(x)
#define __acquire(x)    (void)0
#define __release(x)    (void)0
#define __percpu
#define __kernel
#define __user

/*
 * __unqual_scalar_typeof(x) - Declare an unqualified scalar type, leaving
 *                 non-scalar types unchanged.
 */
/*
 * Prefer C11 _Generic for better compile-times and simpler code. Note: 'char'
 * is not type-compatible with 'signed char', and we define a separate case.
 */
#define __scalar_type_to_expr_cases(type)               \
        unsigned type:  (unsigned type)0,           \
        signed type:    (signed type)0

#define __unqual_scalar_typeof(x) typeof(               \
        _Generic((x),                       \
             char:  (char)0,                \
             __scalar_type_to_expr_cases(char),     \
             __scalar_type_to_expr_cases(short),        \
             __scalar_type_to_expr_cases(int),      \
             __scalar_type_to_expr_cases(long),     \
             __scalar_type_to_expr_cases(long long),    \
             default: (x)))

/* Is this type a native word size -- useful for atomic operations */
#define __native_word(t) \
    (sizeof(t) == sizeof(char) || sizeof(t) == sizeof(short) || \
     sizeof(t) == sizeof(int) || sizeof(t) == sizeof(long))

/* Are two types/vars the same type (ignoring qualifiers)? */
#define __same_type(a, b) \
    __builtin_types_compatible_p(typeof(a), typeof(b))

/*
 * Any place that could be marked with the "alloc_size" attribute is also
 * a place to be marked with the "malloc" attribute. Do this as part of the
 * __alloc_size macro to avoid redundant attributes and to avoid missing a
 * __malloc marking.
 */
#ifdef __alloc_size__
# define __alloc_size(x, ...)   __alloc_size__(x, ## __VA_ARGS__) __malloc
#else
# define __alloc_size(x, ...)   __malloc
#endif

#endif /* __LINUX_COMPILER_TYPES_H */

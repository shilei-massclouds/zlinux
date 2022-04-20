/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * linux/percpu-defs.h - basic definitions for percpu areas
 *
 * DO NOT INCLUDE DIRECTLY OUTSIDE PERCPU IMPLEMENTATION PROPER.
 *
 * This file is separate from linux/percpu.h to avoid cyclic inclusion
 * dependency from arch header files.  Only to be included from
 * asm/percpu.h.
 *
 * This file includes macros necessary to declare percpu sections and
 * variables, and definitions of percpu accessors and operations.  It
 * should provide enough percpu features to arch header files even when
 * they can only include asm/percpu.h to avoid cyclic inclusion dependency.
 */

#ifndef _LINUX_PERCPU_DEFS_H
#define _LINUX_PERCPU_DEFS_H

#define EXPORT_PER_CPU_SYMBOL(var) EXPORT_SYMBOL(var)
#define EXPORT_PER_CPU_SYMBOL_GPL(var) EXPORT_SYMBOL_GPL(var)

/*
 * Accessors and operations.
 */
#ifndef __ASSEMBLY__

/*
 * Add an offset to a pointer but keep the pointer as-is.  Use RELOC_HIDE()
 * to prevent the compiler from making incorrect assumptions about the
 * pointer value.  The weird cast keeps both GCC and sparse happy.
 */
#define SHIFT_PERCPU_PTR(__p, __offset) \
    RELOC_HIDE((typeof(*(__p)) __kernel __force *)(__p), (__offset))

/*
 * __verify_pcpu_ptr() verifies @ptr is a percpu pointer without evaluating
 * @ptr and is invoked once before a percpu area is accessed by all
 * accessors and operations.  This is performed in the generic part of
 * percpu and arch overrides don't need to worry about it; however, if an
 * arch wants to implement an arch-specific percpu accessor or operation,
 * it may use __verify_pcpu_ptr() to verify the parameters.
 *
 * + 0 is required in order to convert the pointer type from a
 * potential array type to a pointer to a single item of the array.
 */
#define __verify_pcpu_ptr(ptr)                      \
do {                                    \
    const void __percpu *__vpp_verify = (typeof((ptr) + 0))NULL;    \
    (void)__vpp_verify;                     \
} while (0)

#define raw_cpu_ptr(ptr)                        \
({                                              \
    __verify_pcpu_ptr(ptr);                     \
    arch_raw_cpu_ptr(ptr);                      \
})

extern void __bad_size_call_parameter(void);

#define __pcpu_size_call(stem, variable, ...)               \
do {                                    \
    __verify_pcpu_ptr(&(variable));                 \
    switch(sizeof(variable)) {                  \
        case 1: stem##1(variable, __VA_ARGS__);break;       \
        case 2: stem##2(variable, __VA_ARGS__);break;       \
        case 4: stem##4(variable, __VA_ARGS__);break;       \
        case 8: stem##8(variable, __VA_ARGS__);break;       \
        default:                        \
            __bad_size_call_parameter();break;      \
    }                               \
} while (0)

#define this_cpu_add(pcp, val)  __pcpu_size_call(this_cpu_add_, pcp, val)
#define this_cpu_sub(pcp, val)  this_cpu_add(pcp, -(typeof(pcp))(val))

#define this_cpu_inc(pcp)       this_cpu_add(pcp, 1)
#define this_cpu_dec(pcp)       this_cpu_sub(pcp, 1)

/*
 * Base implementations of per-CPU variable declarations and definitions, where
 * the section in which the variable is to be placed is provided by the
 * 'sec' argument.  This may be used to affect the parameters governing the
 * variable's storage.
 *
 * NOTE!  The sections for the DECLARE and for the DEFINE must match, lest
 * linkage errors occur due the compiler generating the wrong code to access
 * that section.
 */
#define __PCPU_ATTRS(sec) \
    __percpu __attribute__((section(PER_CPU_BASE_SECTION sec))) \
    PER_CPU_ATTRIBUTES

/*
 * Normal declaration and definition macros.
 */
#define DECLARE_PER_CPU_SECTION(type, name, sec) \
    extern __PCPU_ATTRS(sec) __typeof__(type) name

#define DEFINE_PER_CPU_SECTION(type, name, sec) \
    __PCPU_ATTRS(sec) __typeof__(type) name

/*
 * Variant on the per-CPU variable declaration/definition theme used for
 * ordinary per-CPU variables.
 */
#define DECLARE_PER_CPU(type, name) \
    DECLARE_PER_CPU_SECTION(type, name, "")

#define DEFINE_PER_CPU(type, name) \
    DEFINE_PER_CPU_SECTION(type, name, "")

#endif /* __ASSEMBLY__ */

#endif /* _LINUX_PERCPU_DEFS_H */

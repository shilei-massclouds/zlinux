/* SPDX-License-Identifier: GPL-2.0 OR MIT */
#ifndef __LINUX_OVERFLOW_H
#define __LINUX_OVERFLOW_H

#include <linux/compiler.h>
#include <linux/limits.h>

/*
 * Allows for effectively applying __must_check to a macro so we can have
 * both the type-agnostic benefits of the macros while also being able to
 * enforce that the return value is, in fact, checked.
 */
static inline bool __must_check __must_check_overflow(bool overflow)
{
    return unlikely(overflow);
}

#define check_mul_overflow(a, b, d) __must_check_overflow(({    \
    typeof(a) __a = (a);            \
    typeof(b) __b = (b);            \
    typeof(d) __d = (d);            \
    (void) (&__a == &__b);          \
    (void) (&__a == __d);           \
    __builtin_mul_overflow(__a, __b, __d);  \
}))

/*
 * For simplicity and code hygiene, the fallback code below insists on
 * a, b and *d having the same type (similar to the min() and max()
 * macros), whereas gcc's type-generic overflow checkers accept
 * different types. Hence we don't just make check_add_overflow an
 * alias for __builtin_add_overflow, but add type checks similar to
 * below.
 */
#define check_add_overflow(a, b, d) __must_check_overflow(({    \
    typeof(a) __a = (a);            \
    typeof(b) __b = (b);            \
    typeof(d) __d = (d);            \
    (void) (&__a == &__b);          \
    (void) (&__a == __d);           \
    __builtin_add_overflow(__a, __b, __d);  \
}))

/*
 * Compute a*b+c, returning SIZE_MAX on overflow. Internal helper for
 * struct_size() below.
 */
static inline __must_check size_t __ab_c_size(size_t a, size_t b, size_t c)
{
    size_t bytes;

    if (check_mul_overflow(a, b, &bytes))
        return SIZE_MAX;
    if (check_add_overflow(bytes, c, &bytes))
        return SIZE_MAX;

    return bytes;
}

/**
 * struct_size() - Calculate size of structure with trailing array.
 * @p: Pointer to the structure.
 * @member: Name of the array member.
 * @count: Number of elements in the array.
 *
 * Calculates size of memory needed for structure @p followed by an
 * array of @count number of @member elements.
 *
 * Return: number of bytes needed or SIZE_MAX on overflow.
 */
#define struct_size(p, member, count) \
    __ab_c_size(count, \
                sizeof(*(p)->member) + __must_be_array((p)->member), \
                sizeof(*(p)))

/**
 * size_mul() - Calculate size_t multiplication with saturation at SIZE_MAX
 *
 * @factor1: first factor
 * @factor2: second factor
 *
 * Returns: calculate @factor1 * @factor2, both promoted to size_t,
 * with any overflow causing the return value to be SIZE_MAX. The
 * lvalue must be size_t to avoid implicit type conversion.
 */
static inline size_t __must_check size_mul(size_t factor1, size_t factor2)
{
    size_t bytes;

    if (check_mul_overflow(factor1, factor2, &bytes))
        return SIZE_MAX;

    return bytes;
}

/**
 * array_size() - Calculate size of 2-dimensional array.
 *
 * @a: dimension one
 * @b: dimension two
 *
 * Calculates size of 2-dimensional array: @a * @b.
 *
 * Returns: number of bytes needed to represent the array or SIZE_MAX on
 * overflow.
 */
#define array_size(a, b)    size_mul(a, b)

#endif /* __LINUX_OVERFLOW_H */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COMPILER_ATTRIBUTES_H
#define __LINUX_COMPILER_ATTRIBUTES_H

#define __cold          __attribute__((__cold__))
#define __section(S)    __attribute__((__section__(#S)))
#define __noreturn      __attribute__((__noreturn__))
#define __packed        __attribute__((__packed__))
#define __aligned(x)    __attribute__((__aligned__(x)))

#define __always_inline inline __attribute__((__always_inline__))

#define __attribute_const__ __attribute__((__const__))

#if __has_attribute(__externally_visible__)
# define __visible  __attribute__((__externally_visible__))
#else
# define __visible
#endif

#define __used __attribute__((__used__))

#define noinline    __attribute__((__noinline__))

#define __printf(a, b)  __attribute__((__format__(printf, a, b)))

#if __has_attribute(__designated_init__)
# define __designated_init  __attribute__((__designated_init__))
#else
# define __designated_init
#endif

#endif /* __LINUX_COMPILER_ATTRIBUTES_H */

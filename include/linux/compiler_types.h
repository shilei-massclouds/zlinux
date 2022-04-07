/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_COMPILER_TYPES_H
#define __LINUX_COMPILER_TYPES_H

#ifndef __ASSEMBLY__

#ifdef __KERNEL__

/* Attributes */
#include <linux/compiler_attributes.h>

#if defined(__GNUC__)
#include <linux/compiler-gcc.h>
#else
#error "Unknown compiler"
#endif

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

#endif /* __LINUX_COMPILER_TYPES_H */

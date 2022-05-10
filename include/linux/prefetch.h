/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Generic cache management functions. Everything is arch-specific,
 *  but this header exists to make sure the defines/functions can be
 *  used in a generic way.
 *
 *  2000-11-13  Arjan van de Ven   <arjan@fenrus.demon.nl>
 *
 */

#ifndef _LINUX_PREFETCH_H
#define _LINUX_PREFETCH_H

#include <linux/types.h>
#include <asm/processor.h>
#include <asm/cache.h>

struct page;

#ifndef ARCH_HAS_PREFETCHW
#define prefetchw(x) __builtin_prefetch(x,1)
#endif

#endif /* _LINUX_PREFETCH_H */

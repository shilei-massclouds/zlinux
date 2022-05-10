/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_BITMAP_H
#define __LINUX_BITMAP_H

#ifndef __ASSEMBLY__

//#include <linux/align.h>
#include <linux/bitops.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/types.h>

#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))

#endif /* __ASSEMBLY__ */

#endif /* __LINUX_BITMAP_H */

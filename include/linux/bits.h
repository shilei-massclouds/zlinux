/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_BITS_H
#define __LINUX_BITS_H

#include <linux/const.h>
#include <vdso/bits.h>
#include <asm/bitsperlong.h>

#define BIT_MASK(nr)    (UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)    ((nr) / BITS_PER_LONG)
#define BITS_PER_BYTE   8

#endif  /* __LINUX_BITS_H */

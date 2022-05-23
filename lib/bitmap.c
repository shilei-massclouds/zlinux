// SPDX-License-Identifier: GPL-2.0-only
/*
 * lib/bitmap.c
 * Helper functions for bitmap.h.
 */

#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/ctype.h>
//#include <linux/device.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/thread_info.h>
#include <linux/uaccess.h>

#include <asm/page.h>

//#include "kstrtox.h"

int __bitmap_weight(const unsigned long *bitmap, unsigned int bits)
{
    unsigned int k, lim = bits/BITS_PER_LONG;
    int w = 0;

    for (k = 0; k < lim; k++)
        w += hweight_long(bitmap[k]);

    if (bits % BITS_PER_LONG)
        w += hweight_long(bitmap[k] & BITMAP_LAST_WORD_MASK(bits));

    return w;
}
EXPORT_SYMBOL(__bitmap_weight);

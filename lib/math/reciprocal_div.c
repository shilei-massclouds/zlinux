// SPDX-License-Identifier: GPL-2.0
#include <linux/bitops.h>
#include <linux/bug.h>
#include <linux/export.h>
#include <linux/limits.h>
#include <linux/math.h>
#include <linux/minmax.h>
#include <linux/types.h>

#include <linux/reciprocal_div.h>

/*
 * For a description of the algorithm please have a look at
 * include/linux/reciprocal_div.h
 */

struct reciprocal_value reciprocal_value(u32 d)
{
    u64 m;
    int l;
    struct reciprocal_value R;

    l = fls(d - 1);
    m = ((1ULL << 32) * ((1ULL << l) - d));
    do_div(m, d);
    ++m;
    R.m = (u32)m;
    R.sh1 = min(l, 1);
    R.sh2 = max(l - 1, 0);

    return R;
}
EXPORT_SYMBOL(reciprocal_value);

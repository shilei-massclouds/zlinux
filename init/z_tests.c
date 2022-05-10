// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/z_tests.c
 */

#include <linux/gfp.h>

int z_tests(void)
{
    /* TEST: alloc_page */
    {
        struct page *p = alloc_page(GFP_KERNEL);
        panic("%s: alloc page %pa\n", __func__, p);
    }

    return 0;
}

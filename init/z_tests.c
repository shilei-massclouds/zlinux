// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/z_tests.c
 */

#include <linux/gfp.h>
#include <linux/slab.h>

int z_tests(void)
{
    /* TEST: alloc_page */
    {
        struct page *p = alloc_page(GFP_KERNEL);
        panic("%s: alloc page %pa\n", __func__, p);
    }

    /* TEST: kmalloc */
    {
        struct page *p;
        printk("%s: kmalloc ...\n", __func__);
        p = kmalloc(64, GFP_KERNEL);
        printk("%s: kfree (%pa)...\n", __func__, &p);
        kfree(p);
        panic("%s: alloc/free page\n", __func__);
    }

    return 0;
}

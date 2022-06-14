// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/init/z_tests.c
 */

#include <linux/gfp.h>
#include <linux/slab.h>

#define Z_EXIT_ON_ERROR(func) \
do { \
    if (func() < 0) \
        return -1; \
} while(0)

static int test_alloc_free_page(void)
{
    struct page *p = alloc_page(GFP_KERNEL);
    if (p == NULL)
        return -1;

    __free_page(p);
    return 0;
}

static int test_kmalloc_kfree(void)
{
    struct page *p = kmalloc(64, GFP_KERNEL);
    if (p == NULL)
        return -1;

    kfree(p);
    return 0;
}

int z_tests_early(void)
{
    /* TEST: alloc_page */
    Z_EXIT_ON_ERROR(test_alloc_free_page);

    /* TEST: kmalloc */
    Z_EXIT_ON_ERROR(test_kmalloc_kfree);

    printk("### Z TESTS EARLY OK! ###\n");
    return 0;
}

int z_tests(void)
{
    return 0;
}

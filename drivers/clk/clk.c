// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2010-2011 Canonical Ltd <jeremy.kerr@canonical.com>
 * Copyright (C) 2011-2012 Linaro Ltd <mturquette@linaro.org>
 *
 * Standard functionality for the common clock API.  See Documentation/driver-api/clk.rst
 */

#if 0
#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/clk/clk-conf.h>
#endif
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/of.h>
#include <linux/device.h>
#include <linux/init.h>
//#include <linux/pm_runtime.h>
#include <linux/sched.h>
//#include <linux/clkdev.h>

//#include "clk.h"

extern struct of_device_id __clk_of_table;
static const struct of_device_id __clk_of_table_sentinel
    __used __section("__clk_of_table_end");

/**
 * of_clk_init() - Scan and init clock providers from the DT
 * @matches: array of compatible values and init functions for providers.
 *
 * This function scans the device tree for matching clock providers
 * and calls their initialization functions. It also does it by trying
 * to follow the dependencies.
 */
void __init of_clk_init(const struct of_device_id *matches)
{
    const struct of_device_id *match;
    struct device_node *np;
    struct clock_provider *clk_provider, *next;
    bool is_init_done;
    bool force = false;
    LIST_HEAD(clk_provider_list);

    if (!matches)
        matches = &__clk_of_table;

    /* First prepare the list of the clocks providers */
    for_each_matching_node_and_match(np, matches, &match) {
        struct clock_provider *parent;

        if (!of_device_is_available(np))
            continue;

        panic("%s: 1!\n", __func__);
    }

    while (!list_empty(&clk_provider_list)) {
        panic("%s: 1!\n", __func__);
    }
}

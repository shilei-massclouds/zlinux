// SPDX-License-Identifier: GPL-2.0
#include <linux/of.h>
//#include <linux/slab.h>

#include "of_private.h"

static void of_node_release(struct kobject *kobj)
{
    /* Without CONFIG_OF_DYNAMIC, no nodes gets freed */
}

struct kobj_type of_node_ktype = {
    .release = of_node_release,
};

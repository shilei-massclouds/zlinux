// SPDX-License-Identifier: GPL-2.0
#include <linux/cache.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/pid_namespace.h>
#include "internal.h"

static unsigned self_inum __ro_after_init;

void __init proc_self_init(void)
{
    proc_alloc_inum(&self_inum);
}

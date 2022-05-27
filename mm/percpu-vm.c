// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/percpu-vm.c - vmalloc area based chunk allocation
 *
 * Copyright (C) 2010       SUSE Linux Products GmbH
 * Copyright (C) 2010       Tejun Heo <tj@kernel.org>
 *
 * Chunks are mapped into vmalloc areas and populated page by page.
 * This is the default chunk allocator.
 */
#include "internal.h"

static int __init pcpu_verify_alloc_info(const struct pcpu_alloc_info *ai)
{
    /* no extra restriction */
    return 0;
}


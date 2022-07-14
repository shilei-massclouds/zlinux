// SPDX-License-Identifier: GPL-2.0-or-later
/* Filesystem parameter parser.
 *
 * Copyright (C) 2018 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/export.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/slab.h>
#if 0
#include <linux/security.h>
#include <linux/namei.h>
#endif
#include "internal.h"

static const struct constant_table *
__lookup_constant(const struct constant_table *tbl, const char *name)
{
    for ( ; tbl->name; tbl++)
        if (strcmp(name, tbl->name) == 0)
            return tbl;
    return NULL;
}

/**
 * lookup_constant - Look up a constant by name in an ordered table
 * @tbl: The table of constants to search.
 * @name: The name to look up.
 * @not_found: The value to return if the name is not found.
 */
int lookup_constant(const struct constant_table *tbl, const char *name, int not_found)
{
    const struct constant_table *p = __lookup_constant(tbl, name);

    return p ? p->value : not_found;
}
EXPORT_SYMBOL(lookup_constant);

// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Derived from arch/ppc/mm/extable.c and arch/i386/mm/extable.c.
 *
 * Copyright (C) 2004 Paul Mackerras, IBM Corp.
 */

#include <linux/bsearch.h>
#include <linux/module.h>
#include <linux/init.h>
//#include <linux/sort.h>
#include <linux/uaccess.h>
#include <linux/extable.h>

static inline unsigned long ex_to_insn(const struct exception_table_entry *x)
{
    return (unsigned long)&x->insn + x->insn;
}

static int cmp_ex_search(const void *key, const void *elt)
{
    const struct exception_table_entry *_elt = elt;
    unsigned long _key = *(unsigned long *)key;

    /* avoid overflow */
    if (_key > ex_to_insn(_elt))
        return 1;
    if (_key < ex_to_insn(_elt))
        return -1;
    return 0;
}

/*
 * Search one exception table for an entry corresponding to the
 * given instruction address, and return the address of the entry,
 * or NULL if none is found.
 * We use a binary search, and thus we assume that the table is
 * already sorted.
 */
const struct exception_table_entry *
search_extable(const struct exception_table_entry *base,
               const size_t num,
               unsigned long value)
{
    return bsearch(&value, base, num,
                   sizeof(struct exception_table_entry), cmp_ex_search);
}

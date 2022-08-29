/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_EXTABLE_H
#define _LINUX_EXTABLE_H

#include <linux/stddef.h>   /* for NULL */
#include <linux/types.h>

struct module;
struct exception_table_entry;

const struct exception_table_entry *
search_extable(const struct exception_table_entry *base,
               const size_t num, unsigned long value);

/* For extable.c to search modules' exception tables. */
const struct exception_table_entry *search_module_extables(unsigned long addr);

const struct exception_table_entry *search_exception_tables(unsigned long add);

#endif /* _LINUX_EXTABLE_H */

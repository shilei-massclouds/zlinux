// SPDX-License-Identifier: GPL-2.0-or-later
/* Rewritten by Rusty Russell, on the backs of many others...
   Copyright (C) 2001 Rusty Russell, 2002 Rusty Russell IBM.

*/
#include <linux/elf.h>
//#include <linux/ftrace.h>
//#include <linux/memory.h>
#include <linux/extable.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/init.h>
//#include <linux/kprobes.h>
//#include <linux/filter.h>

#include <asm/sections.h>
#include <linux/uaccess.h>

extern struct exception_table_entry __start___ex_table[];
extern struct exception_table_entry __stop___ex_table[];

/* Given an address, look for it in the kernel exception table */
const
struct exception_table_entry *search_kernel_exception_table(unsigned long addr)
{
    return search_extable(__start___ex_table,
                          __stop___ex_table - __start___ex_table,
                          addr);
}

/* Given an address, look for it in the exception tables. */
const struct exception_table_entry *search_exception_tables(unsigned long addr)
{
    const struct exception_table_entry *e;

    e = search_kernel_exception_table(addr);
    if (!e)
        e = search_module_extables(addr);
    return e;
}

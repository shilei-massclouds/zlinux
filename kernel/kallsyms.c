// SPDX-License-Identifier: GPL-2.0-only
/*
 * kallsyms.c: in-kernel printing of symbolic oopses and stack traces.
 *
 * Rewritten and vastly simplified by Rusty Russell for in-kernel
 * module loader:
 *   Copyright 2002 Rusty Russell <rusty@rustcorp.com.au> IBM Corporation
 *
 * ChangeLog:
 *
 * (25/Aug/2004) Paulo Marques <pmarques@grupopie.com>
 *      Changed the compression method from stem compression to "table lookup"
 *      compression (see scripts/kallsyms.c for a more complete description)
 */
#include <linux/kallsyms.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/kdb.h>
#include <linux/err.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>    /* for cond_resched */
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/filter.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/kernel.h>

/**
 * sprint_symbol_no_offset - Look up a kernel symbol and return it in a text buffer
 * @buffer: buffer to be stored
 * @address: address to lookup
 *
 * This function looks up a kernel symbol with @address and stores its name
 * and module name to @buffer if possible. If no symbol was found, just saves
 * its @address as is.
 *
 * This function returns the number of bytes stored in @buffer.
 */
int sprint_symbol_no_offset(char *buffer, unsigned long address)
{
    return __sprint_symbol(buffer, address, 0, 0, 0);
}
EXPORT_SYMBOL_GPL(sprint_symbol_no_offset);

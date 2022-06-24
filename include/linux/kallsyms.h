/* SPDX-License-Identifier: GPL-2.0 */
/* Rewritten and vastly simplified by Rusty Russell for in-kernel
 * module loader:
 *   Copyright 2002 Rusty Russell <rusty@rustcorp.com.au> IBM Corporation
 */
#ifndef _LINUX_KALLSYMS_H
#define _LINUX_KALLSYMS_H

#include <linux/errno.h>
#include <linux/buildid.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/mm.h>
#include <linux/module.h>

#include <asm/sections.h>

#define KSYM_NAME_LEN 128
#define KSYM_SYMBOL_LEN (sizeof("%s+%#lx/%#lx [%s %s]") + \
            (KSYM_NAME_LEN - 1) + \
            2*(BITS_PER_LONG*3/10) + (MODULE_NAME_LEN - 1) + \
            (BUILD_ID_SIZE_MAX * 2) + 1)

#endif /*_LINUX_KALLSYMS_H*/

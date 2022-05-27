/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VMALLOC_H
#define _LINUX_VMALLOC_H

#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/list.h>
//#include <linux/llist.h>
#include <asm/page.h>       /* pgprot_t */
//#include <linux/rbtree.h>
#include <linux/overflow.h>

//#include <asm/vmalloc.h>

#define VMALLOC_TOTAL (VMALLOC_END - VMALLOC_START)

#endif /* _LINUX_VMALLOC_H */

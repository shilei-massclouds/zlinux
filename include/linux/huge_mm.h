/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HUGE_MM_H
#define _LINUX_HUGE_MM_H

#include <linux/sched/coredump.h>
#include <linux/mm_types.h>

#include <linux/fs.h> /* only for vma_is_dax() */

#define transparent_hugepage_flags 0UL

#define thp_get_unmapped_area   NULL

#endif /* _LINUX_HUGE_MM_H */

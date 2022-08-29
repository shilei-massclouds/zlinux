/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MIGRATE_H
#define _LINUX_MIGRATE_H

#include <linux/mm.h>
#if 0
#include <linux/mempolicy.h>
#endif
#include <linux/migrate_mode.h>
#include <linux/hugetlb.h>

extern bool numa_demotion_enabled;

extern int migrate_page(struct address_space *mapping,
                        struct page *newpage, struct page *page,
                        enum migrate_mode mode);

#endif /* _LINUX_MIGRATE_H */

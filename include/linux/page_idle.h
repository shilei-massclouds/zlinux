/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_PAGE_IDLE_H
#define _LINUX_MM_PAGE_IDLE_H

#include <linux/bitops.h>
#include <linux/page-flags.h>
#if 0
#include <linux/page_ext.h>
#endif

static inline bool folio_test_young(struct folio *folio)
{
    return false;
}

static inline void folio_set_young(struct folio *folio)
{
}

static inline bool folio_test_clear_young(struct folio *folio)
{
    return false;
}

static inline bool folio_test_idle(struct folio *folio)
{
    return false;
}

static inline void folio_set_idle(struct folio *folio)
{
}

static inline void folio_clear_idle(struct folio *folio)
{
}

#endif /* _LINUX_MM_PAGE_IDLE_H */

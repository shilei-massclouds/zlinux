/* SPDX-License-Identifier: GPL-2.0-or-later */
/* memcontrol.h - Memory Controller
 *
 * Copyright IBM Corporation, 2007
 * Author Balbir Singh <balbir@linux.vnet.ibm.com>
 *
 * Copyright 2007 OpenVZ SWsoft Inc
 * Author: Pavel Emelianov <xemul@openvz.org>
 */
#ifndef _LINUX_MEMCONTROL_H
#define _LINUX_MEMCONTROL_H

#include <linux/hardirq.h>
/*
#include <linux/cgroup.h>
#include <linux/vm_event_item.h>
#include <linux/jump_label.h>
#include <linux/page_counter.h>
#include <linux/vmpressure.h>
#include <linux/eventfd.h>
*/
#include <linux/mm.h>
#include <linux/vmstat.h>
#include <linux/writeback.h>
#include <linux/page-flags.h>

/*
 * Bucket for arbitrarily byte-sized objects charged to a memory
 * cgroup. The bucket can be reparented in one piece when the cgroup
 * is destroyed, without having to round up the individual references
 * of all live memory objects in the wild.
 */
struct obj_cgroup {
};

static inline struct lruvec *
folio_lruvec_lock_irqsave(struct folio *folio, unsigned long *flagsp)
{
    struct pglist_data *pgdat = folio_pgdat(folio);

    spin_lock_irqsave(&pgdat->__lruvec.lru_lock, *flagsp);
    return &pgdat->__lruvec;
}

/* Test requires a stable page->memcg binding, see page_memcg() */
static inline bool folio_matches_lruvec(struct folio *folio,
                                        struct lruvec *lruvec)
{
    return lruvec_pgdat(lruvec) == folio_pgdat(folio);
}

static inline void unlock_page_lruvec_irq(struct lruvec *lruvec)
{
    spin_unlock_irq(&lruvec->lru_lock);
}

static inline void unlock_page_lruvec_irqrestore(struct lruvec *lruvec,
                                                 unsigned long flags)
{
    spin_unlock_irqrestore(&lruvec->lru_lock, flags);
}

/* Don't lock again iff page's lruvec locked */
static inline struct lruvec *
folio_lruvec_relock_irqsave(struct folio *folio,
                            struct lruvec *locked_lruvec, unsigned long *flags)
{
    if (locked_lruvec) {
        if (folio_matches_lruvec(folio, locked_lruvec))
            return locked_lruvec;

        unlock_page_lruvec_irqrestore(locked_lruvec, *flags);
    }

    return folio_lruvec_lock_irqsave(folio, flags);
}

#endif /* _LINUX_MEMCONTROL_H */

// SPDX-License-Identifier: GPL-2.0
/*
 * linux/mm/compaction.c
 *
 * Memory compaction for the reduction of external fragmentation. Note that
 * this heavily depends upon page migration to do all the real heavy
 * lifting
 *
 * Copyright IBM Corp. 2007-2010 Mel Gorman <mel@csn.ul.ie>
 */
#include <linux/cpu.h>
#include <linux/swap.h>
#include <linux/migrate.h>
#include <linux/compaction.h>
#include <linux/mm_inline.h>
#include <linux/sched/signal.h>
#include <linux/backing-dev.h>
#include <linux/sysctl.h>
#include <linux/sysfs.h>
#include <linux/page-isolation.h>
#include <linux/kthread.h>
#if 0
#include <linux/freezer.h>
#include <linux/page_owner.h>
#include <linux/psi.h>
#endif
#include "internal.h"

/*
 * This function is called to clear all cached information on pageblocks that
 * should be skipped for page isolation when the migrate and free page scanner
 * meet.
 */
static void __reset_isolation_suitable(struct zone *zone)
{
    panic("%s: END!\n", __func__);
}

void reset_isolation_suitable(pg_data_t *pgdat)
{
    int zoneid;

    for (zoneid = 0; zoneid < MAX_NR_ZONES; zoneid++) {
        struct zone *zone = &pgdat->node_zones[zoneid];
        if (!populated_zone(zone))
            continue;

        /* Only flush if a full compaction finished recently */
        if (zone->compact_blockskip_flush)
            __reset_isolation_suitable(zone);
    }
}

void wakeup_kcompactd(pg_data_t *pgdat, int order, int highest_zoneidx)
{
    if (!order)
        return;

    panic("%s: END!\n", __func__);
}

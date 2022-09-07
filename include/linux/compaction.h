/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_COMPACTION_H
#define _LINUX_COMPACTION_H

/*
 * Determines how hard direct compaction should try to succeed.
 * Lower value means higher priority, analogically to reclaim priority.
 */
enum compact_priority {
    COMPACT_PRIO_SYNC_FULL,
    MIN_COMPACT_PRIORITY = COMPACT_PRIO_SYNC_FULL,
    COMPACT_PRIO_SYNC_LIGHT,
    MIN_COMPACT_COSTLY_PRIORITY = COMPACT_PRIO_SYNC_LIGHT,
    DEF_COMPACT_PRIORITY = COMPACT_PRIO_SYNC_LIGHT,
    COMPACT_PRIO_ASYNC,
    INIT_COMPACT_PRIORITY = COMPACT_PRIO_ASYNC
};

/* Return values for compact_zone() and try_to_compact_pages() */
/* When adding new states, please adjust include/trace/events/compaction.h */
enum compact_result {
    /* For more detailed tracepoint output - internal to compaction */
    COMPACT_NOT_SUITABLE_ZONE,
    /*
     * compaction didn't start as it was not possible or direct reclaim
     * was more suitable
     */
    COMPACT_SKIPPED,
    /* compaction didn't start as it was deferred due to past failures */
    COMPACT_DEFERRED,

    /* For more detailed tracepoint output - internal to compaction */
    COMPACT_NO_SUITABLE_PAGE,
    /* compaction should continue to another pageblock */
    COMPACT_CONTINUE,

    /*
     * The full zone was compacted scanned but wasn't successful to compact
     * suitable pages.
     */
    COMPACT_COMPLETE,
    /*
     * direct compaction has scanned part of the zone but wasn't successful
     * to compact suitable pages.
     */
    COMPACT_PARTIAL_SKIPPED,

    /* compaction terminated prematurely due to lock contentions */
    COMPACT_CONTENDED,

    /*
     * direct compaction terminated after concluding that the allocation
     * should now succeed
     */
    COMPACT_SUCCESS,
};

extern void reset_isolation_suitable(pg_data_t *pgdat);

extern void wakeup_kcompactd(pg_data_t *pgdat, int order,
                             int highest_zoneidx);

/*
 * Number of free order-0 pages that should be available above given watermark
 * to make sure compaction has reasonable chance of not running out of free
 * pages that it needs to isolate as migration target during its work.
 */
static inline unsigned long compact_gap(unsigned int order)
{
    /*
     * Although all the isolations for migration are temporary, compaction
     * free scanner may have up to 1 << order pages on its list and then
     * try to split an (order - 1) free page. At that point, a gap of
     * 1 << order might not be enough, so it's safer to require twice that
     * amount. Note that the number of pages on the list is also
     * effectively limited by COMPACT_CLUSTER_MAX, as that's the maximum
     * that the migrate scanner can have isolated on migrate list, and free
     * scanner is only invoked when the number of isolated free pages is
     * lower than that. But it's not worth to complicate the formula here
     * as a bigger gap for higher orders than strictly necessary can also
     * improve chances of compaction success.
     */
    return 2UL << order;
}

#endif /* _LINUX_COMPACTION_H */

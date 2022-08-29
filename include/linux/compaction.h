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

#endif /* _LINUX_COMPACTION_H */

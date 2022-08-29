// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Swap reorganised 29.12.95, Stephen Tweedie.
 *  kswapd added: 7.1.96  sct
 *  Removed kswapd_ctl limits, and swap out as many pages as needed
 *  to bring the system back to freepages.high: 2.4.97, Rik van Riel.
 *  Zone aware kswapd started 02/00, Kanoj Sarcar (kanoj@sgi.com).
 *  Multiqueue VM started 5.8.00, Rik van Riel.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/highmem.h>
//#include <linux/vmpressure.h>
#include <linux/vmstat.h>
#include <linux/file.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>  /* for try_to_release_page(),
                                   buffer_heads_over_limit */
#include <linux/mm_inline.h>
#include <linux/backing-dev.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/compaction.h>
//#include <linux/notifier.h>
#include <linux/rwsem.h>
#include <linux/delay.h>
#include <linux/kthread.h>
//#include <linux/freezer.h>
#include <linux/memcontrol.h>
#include <linux/migrate.h>
//#include <linux/delayacct.h>
//#include <linux/sysctl.h>
#include <linux/oom.h>
#include <linux/pagevec.h>
#include <linux/prefetch.h>
#include <linux/printk.h>
//#include <linux/dax.h>
//#include <linux/psi.h>

#include <asm/tlbflush.h>
#include <asm/div64.h>

#include <linux/swapops.h>
//#include <linux/balloon_compaction.h>
//#include <linux/sched/sysctl.h>

#include "internal.h"

struct scan_control {
    /* How many pages shrink_list() should reclaim */
    unsigned long nr_to_reclaim;

    /*
     * Nodemask of nodes allowed by the caller. If NULL, all nodes
     * are scanned.
     */
    nodemask_t  *nodemask;

    /*
     * The memory cgroup that hit its limit and as a result is the
     * primary target of this reclaim invocation.
     */
    struct mem_cgroup *target_mem_cgroup;

    /*
     * Scan pressure balancing between anon and file LRUs
     */
    unsigned long   anon_cost;
    unsigned long   file_cost;

    /* Can active pages be deactivated as part of reclaim? */
#define DEACTIVATE_ANON 1
#define DEACTIVATE_FILE 2
    unsigned int may_deactivate:2;
    unsigned int force_deactivate:1;
    unsigned int skipped_deactivate:1;

    /* Writepage batching in laptop mode; RECLAIM_WRITE */
    unsigned int may_writepage:1;

    /* Can mapped pages be reclaimed? */
    unsigned int may_unmap:1;

    /* Can pages be swapped as part of reclaim? */
    unsigned int may_swap:1;

    /*
     * Cgroup memory below memory.low is protected as long as we
     * don't threaten to OOM. If any cgroup is reclaimed at
     * reduced force or passed over entirely due to its memory.low
     * setting (memcg_low_skipped), and nothing is reclaimed as a
     * result, then go back for one more cycle that reclaims the protected
     * memory (memcg_low_reclaim) to avert OOM.
     */
    unsigned int memcg_low_reclaim:1;
    unsigned int memcg_low_skipped:1;

    unsigned int hibernation_mode:1;

    /* One of the zones is ready for compaction */
    unsigned int compaction_ready:1;

    /* There is easily reclaimable cold cache in the current node */
    unsigned int cache_trim_mode:1;

    /* The file pages on the current node are dangerously low */
    unsigned int file_is_tiny:1;

    /* Always discard instead of demoting to lower tier memory */
    unsigned int no_demotion:1;

    /* Allocation order */
    s8 order;

    /* Scan (total_size >> priority) pages at once */
    s8 priority;

    /* The highest zone to isolate pages for reclaim from */
    s8 reclaim_idx;

    /* This context's GFP mask */
    gfp_t gfp_mask;

    /* Incremented by the number of inactive pages that were scanned */
    unsigned long nr_scanned;

    /* Number of pages freed so far during a call to shrink_zones() */
    unsigned long nr_reclaimed;

    struct {
        unsigned int dirty;
        unsigned int unqueued_dirty;
        unsigned int congested;
        unsigned int writeback;
        unsigned int immediate;
        unsigned int file_taken;
        unsigned int taken;
    } nr;

    /* for recording the reclaimed slab by now */
    struct reclaim_state reclaim_state;
};

/*
 * A zone is low on free memory or too fragmented for high-order memory.  If
 * kswapd should reclaim (direct reclaim is deferred), wake it up for the zone's
 * pgdat.  It will wake up kcompactd after reclaiming memory.  If kswapd reclaim
 * has failed or is not needed, still wake up kcompactd if only compaction is
 * needed.
 */
void wakeup_kswapd(struct zone *zone, gfp_t gfp_flags, int order,
                   enum zone_type highest_zoneidx)
{
    pg_data_t *pgdat;
    enum zone_type curr_idx;

    if (!managed_zone(zone))
        return;

    if (!cpuset_zone_allowed(zone, gfp_flags))
        return;

    panic("%s: END!\n", __func__);
}

static bool can_demote(int nid, struct scan_control *sc)
{
    if (!numa_demotion_enabled)
        return false;

    panic("%s: END!\n", __func__);
}

static inline bool can_reclaim_anon_pages(struct mem_cgroup *memcg,
                                          int nid,
                                          struct scan_control *sc)
{
    if (memcg == NULL) {
        /*
         * For non-memcg reclaim, is there
         * space in any swap device?
         */
        if (get_nr_swap_pages() > 0)
            return true;
    } else {
        /* Is the memcg below its swap limit? */
        if (mem_cgroup_get_nr_swap_pages(memcg) > 0)
            return true;
    }

    /*
     * The page can not be swapped.
     *
     * Can it be reclaimed from this node via demotion?
     */
    return can_demote(nid, sc);
}

/*
 * This misses isolated pages which are not accounted for to save counters.
 * As the data only determines if reclaim or compaction continues, it is
 * not expected that isolated pages will be a dominating factor.
 */
unsigned long zone_reclaimable_pages(struct zone *zone)
{
    unsigned long nr;

    nr = zone_page_state_snapshot(zone, NR_ZONE_INACTIVE_FILE) +
        zone_page_state_snapshot(zone, NR_ZONE_ACTIVE_FILE);
    if (can_reclaim_anon_pages(NULL, zone_to_nid(zone), NULL))
        nr += zone_page_state_snapshot(zone, NR_ZONE_INACTIVE_ANON) +
            zone_page_state_snapshot(zone, NR_ZONE_ACTIVE_ANON);

    return nr;
}

static bool allow_direct_reclaim(pg_data_t *pgdat)
{
    struct zone *zone;
    unsigned long pfmemalloc_reserve = 0;
    unsigned long free_pages = 0;
    int i;
    bool wmark_ok;

    if (pgdat->kswapd_failures >= MAX_RECLAIM_RETRIES)
        return true;

    for (i = 0; i <= ZONE_NORMAL; i++) {
        zone = &pgdat->node_zones[i];
        if (!managed_zone(zone))
            continue;

        if (!zone_reclaimable_pages(zone))
            continue;

        pfmemalloc_reserve += min_wmark_pages(zone);
        free_pages += zone_page_state(zone, NR_FREE_PAGES);
    }

    /* If there are no reserves (unexpected config) then do not throttle */
    if (!pfmemalloc_reserve)
        return true;

    wmark_ok = free_pages > pfmemalloc_reserve / 2;
    panic("%s: END!\n", __func__);
}

/*
 * Throttle direct reclaimers if backing storage is backed by the network
 * and the PFMEMALLOC reserve for the preferred node is getting dangerously
 * depleted. kswapd will continue to make progress and wake the processes
 * when the low watermark is reached.
 *
 * Returns true if a fatal signal was delivered during throttling. If this
 * happens, the page allocator should not consider triggering the OOM killer.
 */
static bool throttle_direct_reclaim(gfp_t gfp_mask, struct zonelist *zonelist,
                                    nodemask_t *nodemask)
{
    struct zoneref *z;
    struct zone *zone;
    pg_data_t *pgdat = NULL;

    /*
     * Kernel threads should not be throttled as they may be indirectly
     * responsible for cleaning pages necessary for reclaim to make forward
     * progress. kjournald for example may enter direct reclaim while
     * committing a transaction where throttling it could forcing other
     * processes to block on log_wait_commit().
     */
    if (current->flags & PF_KTHREAD)
        goto out;

#if 0
    /*
     * If a fatal signal is pending, this process should not throttle.
     * It should return quickly so it can exit and free its memory
     */
    if (fatal_signal_pending(current))
        goto out;
#endif

    /*
     * Check if the pfmemalloc reserves are ok by finding the first node
     * with a usable ZONE_NORMAL or lower zone. The expectation is that
     * GFP_KERNEL will be required for allocating network buffers when
     * swapping over the network so ZONE_HIGHMEM is unusable.
     *
     * Throttling is based on the first usable node and throttled processes
     * wait on a queue until kswapd makes progress and wakes them. There
     * is an affinity then between processes waking up and where reclaim
     * progress has been made assuming the process wakes on the same node.
     * More importantly, processes running on remote nodes will not compete
     * for remote pfmemalloc reserves and processes on different nodes
     * should make reasonable progress.
     */
    for_each_zone_zonelist_nodemask(zone, z, zonelist,
                                    gfp_zone(gfp_mask), nodemask) {
        if (zone_idx(zone) > ZONE_NORMAL)
            continue;

        /* Throttle based on the first usable node */
        pgdat = zone->zone_pgdat;
        if (allow_direct_reclaim(pgdat))
            goto out;
        break;
    }

    panic("%s: END!\n", __func__);

 out:
    return false;
}

static void set_task_reclaim_state(struct task_struct *task,
                                   struct reclaim_state *rs)
{
    /* Check for an overwrite */
    WARN_ON_ONCE(rs && task->reclaim_state);

    /* Check for the nulling of an already-nulled member */
    WARN_ON_ONCE(!rs && !task->reclaim_state);

    task->reclaim_state = rs;
}

static bool cgroup_reclaim(struct scan_control *sc)
{
    return sc->target_mem_cgroup;
}

/*
 * This is the main entry point to direct page reclaim.
 *
 * If a full scan of the inactive list fails to free enough memory then we
 * are "out of memory" and something needs to be killed.
 *
 * If the caller is !__GFP_FS then the probability of a failure is reasonably
 * high - the zone may be full of dirty or under-writeback pages, which this
 * caller can't do much about.  We kick the writeback threads and take explicit
 * naps in the hope that some of these pages can be written.  But if the
 * allocating task holds filesystem locks which prevent writeout this might not
 * work, and the allocation attempt will fail.
 *
 * returns: 0, if no pages reclaimed
 *      else, the number of pages reclaimed
 */
static unsigned long do_try_to_free_pages(struct zonelist *zonelist,
                                          struct scan_control *sc)
{
    int initial_priority = sc->priority;
    pg_data_t *last_pgdat;
    struct zoneref *z;
    struct zone *zone;

 retry:

#if 0
    if (!cgroup_reclaim(sc))
        __count_zid_vm_events(ALLOCSTALL, sc->reclaim_idx, 1);
#endif

    do {
#if 0
        vmpressure_prio(sc->gfp_mask, sc->target_mem_cgroup, sc->priority);
        sc->nr_scanned = 0;
        shrink_zones(zonelist, sc);

        if (sc->nr_reclaimed >= sc->nr_to_reclaim)
            break;

        if (sc->compaction_ready)
            break;

        /*
         * If we're getting trouble reclaiming, start doing
         * writepage even in laptop mode.
         */
        if (sc->priority < DEF_PRIORITY - 2)
            sc->may_writepage = 1;
#endif
        panic("%s: 1!\n", __func__);
    } while (--sc->priority >= 0);

    panic("%s: END!\n", __func__);
}

unsigned long try_to_free_pages(struct zonelist *zonelist, int order,
                                gfp_t gfp_mask, nodemask_t *nodemask)
{
    unsigned long nr_reclaimed;
    struct scan_control sc = {
        .nr_to_reclaim = SWAP_CLUSTER_MAX,
        .gfp_mask = current_gfp_context(gfp_mask),
        .reclaim_idx = gfp_zone(gfp_mask),
        .order = order,
        .nodemask = nodemask,
        .priority = DEF_PRIORITY,
        .may_writepage = !laptop_mode,
        .may_unmap = 1,
        .may_swap = 1,
    };

    /*
     * scan_control uses s8 fields for order, priority, and reclaim_idx.
     * Confirm they are large enough for max values.
     */
    BUILD_BUG_ON(MAX_ORDER > S8_MAX);
    BUILD_BUG_ON(DEF_PRIORITY > S8_MAX);
    BUILD_BUG_ON(MAX_NR_ZONES > S8_MAX);

    /*
     * Do not enter reclaim if fatal signal was delivered while throttled.
     * 1 is returned so that the page allocator does not OOM kill at this
     * point.
     */
    if (throttle_direct_reclaim(sc.gfp_mask, zonelist, nodemask))
        return 1;

    set_task_reclaim_state(current, &sc.reclaim_state);

#if 0
    nr_reclaimed = do_try_to_free_pages(zonelist, &sc);
#else
    nr_reclaimed = 0;
    pr_warn("%s: ignore do_try_to_free_pages!\n", __func__);
#endif

    set_task_reclaim_state(current, NULL);

    return nr_reclaimed;
}

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

enum scan_balance {
    SCAN_EQUAL,
    SCAN_FRACT,
    SCAN_ANON,
    SCAN_FILE,
};

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

static LIST_HEAD(shrinker_list);
static DECLARE_RWSEM(shrinker_rwsem);

/*
 * If a kernel thread (such as nfsd for loop-back mounts) services
 * a backing device by writing to the page cache it sets PF_LOCAL_THROTTLE.
 * In that case we should only throttle if the backing device it is
 * writing to is congested.  In other cases it is safe to throttle.
 */
static int current_may_throttle(void)
{
    return !(current->flags & PF_LOCAL_THROTTLE);
}

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
    /* kswapd must be awake if processes are being throttled */
    if (!wmark_ok && waitqueue_active(&pgdat->kswapd_wait)) {
        if (READ_ONCE(pgdat->kswapd_highest_zoneidx) > ZONE_NORMAL)
            WRITE_ONCE(pgdat->kswapd_highest_zoneidx, ZONE_NORMAL);

        wake_up_interruptible(&pgdat->kswapd_wait);
    }

    return wmark_ok;
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

    /* If no zone was usable by the allocation flags then do not throttle */
    if (!pgdat)
        goto out;

    /* Account for the throttling */
    //count_vm_event(PGSCAN_DIRECT_THROTTLE);

#if 0
    /*
     * If the caller cannot enter the filesystem, it's possible that it
     * is due to the caller holding an FS lock or performing a journal
     * transaction in the case of a filesystem like ext[3|4]. In this case,
     * it is not safe to block on pfmemalloc_wait as kswapd could be
     * blocked waiting on the same lock. Instead, throttle for up to a
     * second before continuing.
     */
    if (!(gfp_mask & __GFP_FS))
        wait_event_interruptible_timeout(pgdat->pfmemalloc_wait,
                                         allow_direct_reclaim(pgdat), HZ);
    else
        /* Throttle until kswapd wakes the process */
        wait_event_killable(zone->zone_pgdat->pfmemalloc_wait,
                            allow_direct_reclaim(pgdat));
#endif

#if 0
    if (fatal_signal_pending(current))
        return true;
#endif

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
    return false;
}

/*
 * Returns true if compaction should go ahead for a costly-order request, or
 * the allocation would already succeed without compaction. Return false if we
 * should reclaim first.
 */
static inline bool compaction_ready(struct zone *zone, struct scan_control *sc)
{
    panic("%s: END!\n", __func__);
}

/*
 * The inactive anon list should be small enough that the VM never has
 * to do too much work.
 *
 * The inactive file list should be small enough to leave most memory
 * to the established workingset on the scan-resistant active list,
 * but large enough to avoid thrashing the aggregate readahead window.
 *
 * Both inactive lists should also be large enough that each inactive
 * page has a chance to be referenced again before it is reclaimed.
 *
 * If that fails and refaulting is observed, the inactive list grows.
 *
 * The inactive_ratio is the target ratio of ACTIVE to INACTIVE pages
 * on this LRU, maintained by the pageout code. An inactive_ratio
 * of 3 means 3:1 or 25% of the pages are kept on the inactive list.
 *
 * total     target    max
 * memory    ratio     inactive
 * -------------------------------------
 *   10MB       1         5MB
 *  100MB       1        50MB
 *    1GB       3       250MB
 *   10GB      10       0.9GB
 *  100GB      31         3GB
 *    1TB     101        10GB
 *   10TB     320        32GB
 */
static bool inactive_is_low(struct lruvec *lruvec, enum lru_list inactive_lru)
{
    enum lru_list active_lru = inactive_lru + LRU_ACTIVE;
    unsigned long inactive, active;
    unsigned long inactive_ratio;
    unsigned long gb;

    inactive = lruvec_page_state(lruvec, NR_LRU_BASE + inactive_lru);
    active = lruvec_page_state(lruvec, NR_LRU_BASE + active_lru);

    gb = (inactive + active) >> (30 - PAGE_SHIFT);
    if (gb)
        inactive_ratio = int_sqrt(10 * gb);
    else
        inactive_ratio = 1;

    return inactive * inactive_ratio < active;
}

/**
 * lruvec_lru_size -  Returns the number of pages on the given LRU list.
 * @lruvec: lru vector
 * @lru: lru to use
 * @zone_idx: zones to consider (use MAX_NR_ZONES for the whole LRU list)
 */
static unsigned long lruvec_lru_size(struct lruvec *lruvec, enum lru_list lru,
                                     int zone_idx)
{
    unsigned long size = 0;
    int zid;

    for (zid = 0; zid <= zone_idx && zid < MAX_NR_ZONES; zid++) {
        struct zone *zone = &lruvec_pgdat(lruvec)->node_zones[zid];

        if (!managed_zone(zone))
            continue;

        size += zone_page_state(zone, NR_ZONE_LRU_BASE + lru);
    }
    return size;
}

/*
 * Determine how aggressively the anon and file LRU lists should be
 * scanned.  The relative value of each set of LRU lists is determined
 * by looking at the fraction of the pages scanned we did rotate back
 * onto the active list instead of evict.
 *
 * nr[0] = anon inactive pages to scan; nr[1] = anon active pages to scan
 * nr[2] = file inactive pages to scan; nr[3] = file active pages to scan
 */
static void get_scan_count(struct lruvec *lruvec, struct scan_control *sc,
                           unsigned long *nr)
{
    struct pglist_data *pgdat = lruvec_pgdat(lruvec);
    struct mem_cgroup *memcg = NULL;
    unsigned long anon_cost, file_cost, total_cost;
    int swappiness = mem_cgroup_swappiness(memcg);
    u64 fraction[ANON_AND_FILE];
    u64 denominator = 0;    /* gcc */
    enum scan_balance scan_balance;
    unsigned long ap, fp;
    enum lru_list lru;

    /* If we have no swap space, do not bother scanning anon pages. */
    if (!sc->may_swap || !can_reclaim_anon_pages(memcg, pgdat->node_id, sc)) {
        scan_balance = SCAN_FILE;
        goto out;
    }

    panic("%s: END!\n", __func__);

 out:
    for_each_evictable_lru(lru) {
        int file = is_file_lru(lru);
        unsigned long lruvec_size;
        unsigned long low, min;
        unsigned long scan;

        lruvec_size = lruvec_lru_size(lruvec, lru, sc->reclaim_idx);
        min = low = 0;
        scan = lruvec_size;

        scan >>= sc->priority;

        switch (scan_balance) {
        case SCAN_EQUAL:
            /* Scan lists relative to size */
            break;
        case SCAN_FRACT:
            /*
             * Scan types proportional to swappiness and
             * their relative recent reclaim efficiency.
             * Make sure we don't miss the last page on
             * the offlined memory cgroups because of a
             * round-off error.
             */
            scan = div64_u64(scan * fraction[file], denominator);
            break;
        case SCAN_FILE:
        case SCAN_ANON:
            /* Scan one type exclusively */
            if ((scan_balance == SCAN_FILE) != file)
                scan = 0;
            break;
        default:
            /* Look ma, no brain */
            BUG();
        }

        nr[lru] = scan;
    }
}

/*
 * Anonymous LRU management is a waste if there is
 * ultimately no way to reclaim the memory.
 */
static bool can_age_anon_pages(struct pglist_data *pgdat,
                               struct scan_control *sc)
{
    /* Aging the anon LRU is valuable if swap is present: */
    if (total_swap_pages > 0)
        return true;

    /* Also valuable if anon pages can be demoted: */
    return can_demote(pgdat->node_id, sc);
}

/*
 * shrink_active_list() moves pages from the active LRU to the inactive LRU.
 *
 * We move them the other way if the page is referenced by one or more
 * processes.
 *
 * If the pages are mostly unmapped, the processing is fast and it is
 * appropriate to hold lru_lock across the whole operation.  But if
 * the pages are mapped, the processing is slow (folio_referenced()), so
 * we should drop lru_lock around each page.  It's impossible to balance
 * this, so instead we remove the pages from the LRU while processing them.
 * It is safe to rely on PG_active against the non-LRU pages in here because
 * nobody will play with that bit on a non-LRU page.
 *
 * The downside is that we have to touch page->_refcount against each page.
 * But we had to alter page->flags anyway.
 */
static void shrink_active_list(unsigned long nr_to_scan,
                               struct lruvec *lruvec,
                               struct scan_control *sc,
                               enum lru_list lru)
{
    panic("%s: END!\n", __func__);
}

/*
 * A direct reclaimer may isolate SWAP_CLUSTER_MAX pages from the LRU list and
 * then get rescheduled. When there are massive number of tasks doing page
 * allocation, such sleeping direct reclaimers may keep piling up on each CPU,
 * the LRU list will go small and be scanned faster than necessary, leading to
 * unnecessary swapping, thrashing and OOM.
 */
static int too_many_isolated(struct pglist_data *pgdat, int file,
                             struct scan_control *sc)
{
    unsigned long inactive, isolated;
    bool too_many;

    if (current_is_kswapd())
        return 0;

    if (file) {
        inactive = node_page_state(pgdat, NR_INACTIVE_FILE);
        isolated = node_page_state(pgdat, NR_ISOLATED_FILE);
    } else {
        inactive = node_page_state(pgdat, NR_INACTIVE_ANON);
        isolated = node_page_state(pgdat, NR_ISOLATED_ANON);
    }

    /*
     * GFP_NOIO/GFP_NOFS callers are allowed to isolate more pages, so they
     * won't get blocked by normal direct-reclaimers, forming a circular
     * deadlock.
     */
    if ((sc->gfp_mask & (__GFP_IO | __GFP_FS)) == (__GFP_IO | __GFP_FS))
        inactive >>= 3;

    too_many = isolated > inactive;

    /* Wake up tasks throttled due to too_many_isolated. */
    if (!too_many)
        wake_throttle_isolated(pgdat);

    return too_many;
}

void reclaim_throttle(pg_data_t *pgdat, enum vmscan_throttle_state reason)
{
    panic("%s: END!\n", __func__);
}

#define prefetchw_prev_lru_page(_page, _base, _field) do { } while (0)

/*
 * Update LRU sizes after isolating pages. The LRU size updates must
 * be complete before mem_cgroup_update_lru_size due to a sanity check.
 */
static __always_inline
void update_lru_sizes(struct lruvec *lruvec,
                      enum lru_list lru, unsigned long *nr_zone_taken)
{
    int zid;

    for (zid = 0; zid < MAX_NR_ZONES; zid++) {
        if (!nr_zone_taken[zid])
            continue;

        update_lru_size(lruvec, lru, zid, -nr_zone_taken[zid]);
    }

}

/*
 * Isolating page from the lruvec to fill in @dst list by nr_to_scan times.
 *
 * lruvec->lru_lock is heavily contended.  Some of the functions that
 * shrink the lists perform better by taking out a batch of pages
 * and working on them outside the LRU lock.
 *
 * For pagecache intensive workloads, this function is the hottest
 * spot in the kernel (apart from copy_*_user functions).
 *
 * Lru_lock must be held before calling this function.
 *
 * @nr_to_scan: The number of eligible pages to look through on the list.
 * @lruvec: The LRU vector to pull pages from.
 * @dst:    The temp list to put pages on to.
 * @nr_scanned: The number of pages that were scanned.
 * @sc:     The scan_control struct for this reclaim session
 * @lru:    LRU list id for isolating
 *
 * returns how many pages were moved onto *@dst.
 */
static unsigned long isolate_lru_pages(unsigned long nr_to_scan,
                                       struct lruvec *lruvec,
                                       struct list_head *dst,
                                       unsigned long *nr_scanned,
                                       struct scan_control *sc,
                                       enum lru_list lru)
{
    struct list_head *src = &lruvec->lists[lru];
    unsigned long nr_taken = 0;
    unsigned long nr_zone_taken[MAX_NR_ZONES] = { 0 };
    unsigned long nr_skipped[MAX_NR_ZONES] = { 0, };
    unsigned long skipped = 0;
    unsigned long scan, total_scan, nr_pages;
    LIST_HEAD(pages_skipped);

    total_scan = 0;
    scan = 0;
    while (scan < nr_to_scan && !list_empty(src)) {
        struct list_head *move_to = src;
        struct page *page;

        page = lru_to_page(src);
        prefetchw_prev_lru_page(page, src, flags);

        nr_pages = compound_nr(page);
        total_scan += nr_pages;

        if (page_zonenum(page) > sc->reclaim_idx) {
            nr_skipped[page_zonenum(page)] += nr_pages;
            move_to = &pages_skipped;
            goto move;
        }

        /*
         * Do not count skipped pages because that makes the function
         * return with no isolated pages if the LRU mostly contains
         * ineligible pages.  This causes the VM to not reclaim any
         * pages, triggering a premature OOM.
         * Account all tail pages of THP.
         */
        scan += nr_pages;

        if (!PageLRU(page))
            goto move;
        if (!sc->may_unmap && page_mapped(page))
            goto move;

        /*
         * Be careful not to clear PageLRU until after we're
         * sure the page is not being freed elsewhere -- the
         * page release code relies on it.
         */
        if (unlikely(!get_page_unless_zero(page)))
            goto move;

        if (!TestClearPageLRU(page)) {
            /* Another thread is already isolating this page */
            put_page(page);
            goto move;
        }

        nr_taken += nr_pages;
        nr_zone_taken[page_zonenum(page)] += nr_pages;
        move_to = dst;

     move:
        list_move(&page->lru, move_to);
    }

    /*
     * Splice any skipped pages to the start of the LRU list. Note that
     * this disrupts the LRU order when reclaiming for lower zones but
     * we cannot splice to the tail. If we did then the SWAP_CLUSTER_MAX
     * scanning would soon rescan the same pages to skip and put the
     * system at risk of premature OOM.
     */
    if (!list_empty(&pages_skipped)) {
        int zid;

        list_splice(&pages_skipped, src);
        for (zid = 0; zid < MAX_NR_ZONES; zid++) {
            if (!nr_skipped[zid])
                continue;

            __count_zid_vm_events(PGSCAN_SKIP, zid, nr_skipped[zid]);
            skipped += nr_skipped[zid];
        }
    }

    *nr_scanned = total_scan;
    update_lru_sizes(lruvec, lru, nr_zone_taken);
    return nr_taken;
}

enum page_references {
    PAGEREF_RECLAIM,
    PAGEREF_RECLAIM_CLEAN,
    PAGEREF_KEEP,
    PAGEREF_ACTIVATE,
};

/*
 * shrink_page_list() returns the number of reclaimed pages
 */
static unsigned int shrink_page_list(struct list_head *page_list,
                                     struct pglist_data *pgdat,
                                     struct scan_control *sc,
                                     struct reclaim_stat *stat,
                                     bool ignore_references)
{
    LIST_HEAD(ret_pages);
    LIST_HEAD(free_pages);
    LIST_HEAD(demote_pages);
    unsigned int nr_reclaimed = 0;
    unsigned int pgactivate = 0;
    bool do_demote_pass;

    memset(stat, 0, sizeof(*stat));
    cond_resched();
    do_demote_pass = can_demote(pgdat->node_id, sc);

 retry:
    while (!list_empty(page_list)) {
        struct address_space *mapping;
        struct page *page;
        struct folio *folio;
        enum page_references references = PAGEREF_RECLAIM;
        bool dirty, writeback, may_enter_fs;
        unsigned int nr_pages;

        cond_resched();

        folio = lru_to_folio(page_list);
        list_del(&folio->lru);
        page = &folio->page;

        if (!trylock_page(page))
            goto keep;

        VM_BUG_ON_PAGE(PageActive(page), page);

        nr_pages = compound_nr(page);

        /* Account the number of base pages even though THP */
        sc->nr_scanned += nr_pages;

        if (unlikely(!page_evictable(page)))
            goto activate_locked;

        if (!sc->may_unmap && page_mapped(page))
            goto keep_locked;

        may_enter_fs = (sc->gfp_mask & __GFP_FS) ||
            (PageSwapCache(page) && (sc->gfp_mask & __GFP_IO));

        /*
         * The number of dirty pages determines if a node is marked
         * reclaim_congested. kswapd will stall and start writing
         * pages if the tail of the LRU is all dirty unqueued pages.
         */
        folio_check_dirty_writeback(folio, &dirty, &writeback);
        if (dirty || writeback)
            stat->nr_dirty += nr_pages;

        panic("%s: 1!\n", __func__);

     activate_locked:
        /* Not a candidate for swapping, so reclaim swap space. */
        if (PageSwapCache(page) &&
            (mem_cgroup_swap_full(page) || PageMlocked(page)))
            try_to_free_swap(page);
        VM_BUG_ON_PAGE(PageActive(page), page);
        if (!PageMlocked(page)) {
            int type = page_is_file_lru(page);
            SetPageActive(page);
            stat->nr_activate[type] += nr_pages;
        }
     keep_locked:
        unlock_page(page);
     keep:
        list_add(&page->lru, &ret_pages);
        VM_BUG_ON_PAGE(PageLRU(page) || PageUnevictable(page), page);
    }

    panic("%s: END!\n", __func__);
}

/*
 * shrink_inactive_list() is a helper for shrink_node().  It returns the number
 * of reclaimed pages
 */
static unsigned long
shrink_inactive_list(unsigned long nr_to_scan, struct lruvec *lruvec,
                     struct scan_control *sc, enum lru_list lru)
{
    LIST_HEAD(page_list);
    unsigned long nr_scanned;
    unsigned int nr_reclaimed = 0;
    unsigned long nr_taken;
    struct reclaim_stat stat;
    bool file = is_file_lru(lru);
    enum vm_event_item item;
    struct pglist_data *pgdat = lruvec_pgdat(lruvec);
    bool stalled = false;

    while (unlikely(too_many_isolated(pgdat, file, sc))) {
        if (stalled)
            return 0;

        /* wait a bit for the reclaimer. */
        stalled = true;
        reclaim_throttle(pgdat, VMSCAN_THROTTLE_ISOLATED);

#if 0
        /* We are about to die and free our memory. Return now. */
        if (fatal_signal_pending(current))
            return SWAP_CLUSTER_MAX;
#endif
    }

    lru_add_drain();

    spin_lock_irq(&lruvec->lru_lock);

    nr_taken = isolate_lru_pages(nr_to_scan, lruvec, &page_list,
                                 &nr_scanned, sc, lru);

    __mod_node_page_state(pgdat, NR_ISOLATED_ANON + file, nr_taken);
    item = current_is_kswapd() ? PGSCAN_KSWAPD : PGSCAN_DIRECT;
    if (!cgroup_reclaim(sc))
        __count_vm_events(item, nr_scanned);
    __count_vm_events(PGSCAN_ANON + file, nr_scanned);

    spin_unlock_irq(&lruvec->lru_lock);

    if (nr_taken == 0)
        return 0;

    nr_reclaimed = shrink_page_list(&page_list, pgdat, sc, &stat, false);

    spin_lock_irq(&lruvec->lru_lock);

    panic("%s: END!\n", __func__);
}

static unsigned long shrink_list(enum lru_list lru, unsigned long nr_to_scan,
                                 struct lruvec *lruvec, struct scan_control *sc)
{
    if (is_active_lru(lru)) {
        if (sc->may_deactivate & (1 << is_file_lru(lru)))
            shrink_active_list(nr_to_scan, lruvec, sc, lru);
        else
            sc->skipped_deactivate = 1;
        return 0;
    }

    return shrink_inactive_list(nr_to_scan, lruvec, sc, lru);
}

static void shrink_lruvec(struct lruvec *lruvec, struct scan_control *sc)
{
    unsigned long nr[NR_LRU_LISTS];
    unsigned long targets[NR_LRU_LISTS];
    unsigned long nr_to_scan;
    enum lru_list lru;
    unsigned long nr_reclaimed = 0;
    unsigned long nr_to_reclaim = sc->nr_to_reclaim;
    struct blk_plug plug;
    bool scan_adjusted;

    get_scan_count(lruvec, sc, nr);

    /* Record the original scan target for proportional adjustments later */
    memcpy(targets, nr, sizeof(nr));

    /*
     * Global reclaiming within direct reclaim at DEF_PRIORITY is a normal
     * event that can occur when there is little memory pressure e.g.
     * multiple streaming readers/writers. Hence, we do not abort scanning
     * when the requested number of pages are reclaimed when scanning at
     * DEF_PRIORITY on the assumption that the fact we are direct
     * reclaiming implies that kswapd is not keeping up and it is best to
     * do a batch of work at once. For memcg reclaim one check is made to
     * abort proportional reclaim if either the file or anon lru has already
     * dropped to zero at the first pass.
     */
    scan_adjusted = (!cgroup_reclaim(sc) && !current_is_kswapd() &&
                     sc->priority == DEF_PRIORITY);

    blk_start_plug(&plug);
    while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
           nr[LRU_INACTIVE_FILE]) {
        unsigned long nr_anon, nr_file, percentage;
        unsigned long nr_scanned;

        for_each_evictable_lru(lru) {
            if (nr[lru]) {
                nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
                nr[lru] -= nr_to_scan;

                nr_reclaimed += shrink_list(lru, nr_to_scan, lruvec, sc);
            }
        }

        panic("%s: 1!\n", __func__);
    }
    blk_finish_plug(&plug);
    sc->nr_reclaimed += nr_reclaimed;

    /*
     * Even if we did not try to evict anon pages at all, we want to
     * rebalance the anon lru active/inactive ratio.
     */
    if (can_age_anon_pages(lruvec_pgdat(lruvec), sc) &&
        inactive_is_low(lruvec, LRU_INACTIVE_ANON))
        shrink_active_list(SWAP_CLUSTER_MAX, lruvec, sc, LRU_ACTIVE_ANON);
}

static unsigned long do_shrink_slab(struct shrink_control *shrinkctl,
                                    struct shrinker *shrinker, int priority)
{
    panic("%s: END!\n", __func__);
}

/**
 * shrink_slab - shrink slab caches
 * @gfp_mask: allocation context
 * @nid: node whose slab caches to target
 * @memcg: memory cgroup whose slab caches to target
 * @priority: the reclaim priority
 *
 * Call the shrink functions to age shrinkable caches.
 *
 * @nid is passed along to shrinkers with SHRINKER_NUMA_AWARE set,
 * unaware shrinkers will receive a node id of 0 instead.
 *
 * @memcg specifies the memory cgroup to target. Unaware shrinkers
 * are called only if it is the root cgroup.
 *
 * @priority is sc->priority, we take the number of objects and >> by priority
 * in order to get the scan target.
 *
 * Returns the number of reclaimed slab objects.
 */
static unsigned long shrink_slab(gfp_t gfp_mask, int nid,
                                 struct mem_cgroup *memcg,
                                 int priority)
{
    unsigned long ret, freed = 0;
    struct shrinker *shrinker;

    if (!down_read_trylock(&shrinker_rwsem))
        goto out;

    list_for_each_entry(shrinker, &shrinker_list, list) {
        struct shrink_control sc = {
            .gfp_mask = gfp_mask,
            .nid = nid,
            .memcg = memcg,
        };

        ret = do_shrink_slab(&sc, shrinker, priority);
        if (ret == SHRINK_EMPTY)
            ret = 0;
        freed += ret;

        panic("%s: 1!\n", __func__);
    }

    up_read(&shrinker_rwsem);

 out:
    cond_resched();
    return freed;
}

static void shrink_node_memcgs(pg_data_t *pgdat, struct scan_control *sc)
{
    do {
        struct lruvec *lruvec = mem_cgroup_lruvec(NULL, pgdat);
        unsigned long reclaimed;
        unsigned long scanned;

        /*
         * This loop can become CPU-bound when target memcgs
         * aren't eligible for reclaim - either because they
         * don't have any reclaimable pages, or because their
         * memory is explicitly protected. Avoid soft lockups.
         */
        cond_resched();

        reclaimed = sc->nr_reclaimed;
        scanned = sc->nr_scanned;

        shrink_lruvec(lruvec, sc);

        shrink_slab(sc->gfp_mask, pgdat->node_id, NULL, sc->priority);
    } while (0);
}

/* Use reclaim/compaction for costly allocs or under memory pressure */
static bool in_reclaim_compaction(struct scan_control *sc)
{
    if (sc->order && (sc->order > PAGE_ALLOC_COSTLY_ORDER ||
                      sc->priority < DEF_PRIORITY - 2))
        return true;

    return false;
}

/*
 * Reclaim/compaction is used for high-order allocation requests. It reclaims
 * order-0 pages before compacting the zone. should_continue_reclaim() returns
 * true if more pages should be reclaimed such that when the page allocator
 * calls try_to_compact_pages() that it will have enough free pages to succeed.
 * It will give up earlier than that if there is difficulty reclaiming pages.
 */
static inline bool should_continue_reclaim(struct pglist_data *pgdat,
                                           unsigned long nr_reclaimed,
                                           struct scan_control *sc)
{
    unsigned long pages_for_compaction;
    unsigned long inactive_lru_pages;
    int z;

    /* If not in reclaim/compaction mode, stop */
    if (!in_reclaim_compaction(sc))
        return false;

    /*
     * Stop if we failed to reclaim any pages from the last SWAP_CLUSTER_MAX
     * number of pages that were scanned. This will return to the caller
     * with the risk reclaim/compaction and the resulting allocation attempt
     * fails. In the past we have tried harder for __GFP_RETRY_MAYFAIL
     * allocations through requiring that the full LRU list has been scanned
     * first, by assuming that zero delta of sc->nr_scanned means full LRU
     * scan, but that approximation was wrong, and there were corner cases
     * where always a non-zero amount of pages were scanned.
     */
    if (!nr_reclaimed)
        return false;

    panic("%s: END!\n", __func__);
}

static void shrink_node(pg_data_t *pgdat, struct scan_control *sc)
{
    struct reclaim_state *reclaim_state = current->reclaim_state;
    unsigned long nr_reclaimed, nr_scanned;
    struct lruvec *target_lruvec;
    bool reclaimable = false;
    unsigned long file;

    target_lruvec = &pgdat->__lruvec;

 again:
    memset(&sc->nr, 0, sizeof(sc->nr));

    nr_reclaimed = sc->nr_reclaimed;
    nr_scanned = sc->nr_scanned;

    /*
     * Determine the scan balance between anon and file LRUs.
     */
    spin_lock_irq(&target_lruvec->lru_lock);
    sc->anon_cost = target_lruvec->anon_cost;
    sc->file_cost = target_lruvec->file_cost;
    spin_unlock_irq(&target_lruvec->lru_lock);

    /*
     * Target desirable inactive:active list ratios for the anon
     * and file LRU lists.
     */
    if (!sc->force_deactivate) {
        unsigned long refaults;

        refaults = lruvec_page_state(target_lruvec, WORKINGSET_ACTIVATE_ANON);
        if (refaults != target_lruvec->refaults[0] ||
            inactive_is_low(target_lruvec, LRU_INACTIVE_ANON))
            sc->may_deactivate |= DEACTIVATE_ANON;
        else
            sc->may_deactivate &= ~DEACTIVATE_ANON;

        /*
         * When refaults are being observed, it means a new
         * workingset is being established. Deactivate to get
         * rid of any stale active pages quickly.
         */
        refaults = lruvec_page_state(target_lruvec, WORKINGSET_ACTIVATE_FILE);
        if (refaults != target_lruvec->refaults[1] ||
            inactive_is_low(target_lruvec, LRU_INACTIVE_FILE))
            sc->may_deactivate |= DEACTIVATE_FILE;
        else
            sc->may_deactivate &= ~DEACTIVATE_FILE;
    } else
        sc->may_deactivate = DEACTIVATE_ANON | DEACTIVATE_FILE;

    /*
     * If we have plenty of inactive file pages that aren't
     * thrashing, try to reclaim those first before touching
     * anonymous pages.
     */
    file = lruvec_page_state(target_lruvec, NR_INACTIVE_FILE);
    if (file >> sc->priority && !(sc->may_deactivate & DEACTIVATE_FILE))
        sc->cache_trim_mode = 1;
    else
        sc->cache_trim_mode = 0;

    /*
     * Prevent the reclaimer from falling into the cache trap: as
     * cache pages start out inactive, every cache fault will tip
     * the scan balance towards the file LRU.  And as the file LRU
     * shrinks, so does the window for rotation from references.
     * This means we have a runaway feedback loop where a tiny
     * thrashing file LRU becomes infinitely more attractive than
     * anon pages.  Try to detect this based on file LRU size.
     */
    {
        unsigned long total_high_wmark = 0;
        unsigned long free, anon;
        int z;

        free = sum_zone_node_page_state(pgdat->node_id, NR_FREE_PAGES);
        file = node_page_state(pgdat, NR_ACTIVE_FILE) +
               node_page_state(pgdat, NR_INACTIVE_FILE);

        for (z = 0; z < MAX_NR_ZONES; z++) {
            struct zone *zone = &pgdat->node_zones[z];
            if (!managed_zone(zone))
                continue;

            total_high_wmark += high_wmark_pages(zone);
        }

        /*
         * Consider anon: if that's low too, this isn't a
         * runaway file reclaim problem, but rather just
         * extreme pressure. Reclaim as per usual then.
         */
        anon = node_page_state(pgdat, NR_INACTIVE_ANON);

        sc->file_is_tiny = file + free <= total_high_wmark &&
            !(sc->may_deactivate & DEACTIVATE_ANON) && anon >> sc->priority;
    }

    shrink_node_memcgs(pgdat, sc);

    if (reclaim_state) {
        sc->nr_reclaimed += reclaim_state->reclaimed_slab;
        reclaim_state->reclaimed_slab = 0;
    }

    if (sc->nr_reclaimed - nr_reclaimed)
        reclaimable = true;

    if (current_is_kswapd()) {
        panic("%s: 1!\n", __func__);
    }

    /*
     * Tag a node/memcg as congested if all the dirty pages were marked
     * for writeback and immediate reclaim (counted in nr.congested).
     *
     * Legacy memcg will stall in page writeback so avoid forcibly
     * stalling in reclaim_throttle().
     */
    if ((current_is_kswapd() || (cgroup_reclaim(sc))) &&
        sc->nr.dirty && sc->nr.dirty == sc->nr.congested)
        set_bit(LRUVEC_CONGESTED, &target_lruvec->flags);

    /*
     * Stall direct reclaim for IO completions if the lruvec is
     * node is congested. Allow kswapd to continue until it
     * starts encountering unqueued dirty pages or cycling through
     * the LRU too quickly.
     */
    if (!current_is_kswapd() && current_may_throttle() &&
        !sc->hibernation_mode &&
        test_bit(LRUVEC_CONGESTED, &target_lruvec->flags))
        reclaim_throttle(pgdat, VMSCAN_THROTTLE_CONGESTED);

    if (should_continue_reclaim(pgdat, sc->nr_reclaimed - nr_reclaimed, sc))
        goto again;

    /*
     * Kswapd gives up on balancing particular nodes after too
     * many failures to reclaim anything from them and goes to
     * sleep. On reclaim progress, reset the failure counter. A
     * successful direct reclaim run will revive a dormant kswapd.
     */
    if (reclaimable)
        pgdat->kswapd_failures = 0;
}

static void consider_reclaim_throttle(pg_data_t *pgdat, struct scan_control *sc)
{
    /*
     * If reclaim is making progress greater than 12% efficiency then
     * wake all the NOPROGRESS throttled tasks.
     */
    if (sc->nr_reclaimed > (sc->nr_scanned >> 3)) {
        wait_queue_head_t *wqh;

        wqh = &pgdat->reclaim_wait[VMSCAN_THROTTLE_NOPROGRESS];
        if (waitqueue_active(wqh))
            wake_up(wqh);

        return;
    }

    /*
     * Do not throttle kswapd or cgroup reclaim on NOPROGRESS as it will
     * throttle on VMSCAN_THROTTLE_WRITEBACK if there are too many pages
     * under writeback and marked for immediate reclaim at the tail of the
     * LRU.
     */
    if (current_is_kswapd() || cgroup_reclaim(sc))
        return;

    /* Throttle if making no progress at high prioities. */
    if (sc->priority == 1 && !sc->nr_reclaimed)
        reclaim_throttle(pgdat, VMSCAN_THROTTLE_NOPROGRESS);
}

/*
 * This is the direct reclaim path, for page-allocating processes.  We only
 * try to reclaim pages from zones which will satisfy the caller's allocation
 * request.
 *
 * If a zone is deemed to be full of pinned pages then just give it a light
 * scan then give up on it.
 */
static void shrink_zones(struct zonelist *zonelist, struct scan_control *sc)
{
    struct zoneref *z;
    struct zone *zone;
    unsigned long nr_soft_reclaimed;
    unsigned long nr_soft_scanned;
    gfp_t orig_mask;
    pg_data_t *last_pgdat = NULL;
    pg_data_t *first_pgdat = NULL;

    /*
     * If the number of buffer_heads in the machine exceeds the maximum
     * allowed level, force direct reclaim to scan the highmem zone as
     * highmem pages could be pinning lowmem pages storing buffer_heads
     */
    orig_mask = sc->gfp_mask;
    if (buffer_heads_over_limit) {
        sc->gfp_mask |= __GFP_HIGHMEM;
        sc->reclaim_idx = gfp_zone(sc->gfp_mask);
    }

    for_each_zone_zonelist_nodemask(zone, z, zonelist,
                                    sc->reclaim_idx, sc->nodemask) {
        /*
         * Take care memory controller reclaiming has small influence
         * to global LRU.
         */
        if (!cpuset_zone_allowed(zone, GFP_KERNEL | __GFP_HARDWALL))
            continue;

        /*
         * If we already have plenty of memory free for
         * compaction in this zone, don't free any more.
         * Even though compaction is invoked for any
         * non-zero order, only frequent costly order
         * reclamation is disruptive enough to become a
         * noticeable problem, like transparent huge
         * page allocations.
         */
        if (sc->order > PAGE_ALLOC_COSTLY_ORDER &&
            compaction_ready(zone, sc)) {
            sc->compaction_ready = true;
            continue;
        }

        /*
         * Shrink each node in the zonelist once. If the
         * zonelist is ordered by zone (not the default) then a
         * node may be shrunk multiple times but in that case
         * the user prefers lower zones being preserved.
         */
        if (zone->zone_pgdat == last_pgdat)
            continue;

        /*
         * This steals pages from memory cgroups over softlimit
         * and returns the number of reclaimed pages and
         * scanned pages. This works for global memory pressure
         * and balancing, not for a memcg's limit.
         */
        nr_soft_scanned = 0;
        nr_soft_reclaimed = 0;
        sc->nr_reclaimed += nr_soft_reclaimed;
        sc->nr_scanned += nr_soft_scanned;
        /* need some check for avoid more shrink_zone() */

        if (!first_pgdat)
            first_pgdat = zone->zone_pgdat;

        /* See comment about same check for global reclaim above */
        if (zone->zone_pgdat == last_pgdat)
            continue;
        last_pgdat = zone->zone_pgdat;
        shrink_node(zone->zone_pgdat, sc);
    }

    if (first_pgdat)
        consider_reclaim_throttle(first_pgdat, sc);

    /*
     * Restore to original mask to avoid the impact on the caller if we
     * promoted it to __GFP_HIGHMEM.
     */
    sc->gfp_mask = orig_mask;
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

    __count_zid_vm_events(ALLOCSTALL, sc->reclaim_idx, 1);

    do {
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
    } while (--sc->priority >= 0);

    last_pgdat = NULL;
    for_each_zone_zonelist_nodemask(zone, z, zonelist, sc->reclaim_idx,
                                    sc->nodemask) {
        panic("%s: 1!\n", __func__);
    }

    if (sc->nr_reclaimed)
        return sc->nr_reclaimed;

    /* Aborted reclaim to try compaction? don't OOM, then */
    if (sc->compaction_ready)
        return 1;

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

    nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

    set_task_reclaim_state(current, NULL);

    return nr_reclaimed;
}

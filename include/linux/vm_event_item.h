/* SPDX-License-Identifier: GPL-2.0 */
#ifndef VM_EVENT_ITEM_H_INCLUDED
#define VM_EVENT_ITEM_H_INCLUDED

#define DMA_ZONE(xx)
#define DMA32_ZONE(xx) xx##_DMA32,
#define HIGHMEM_ZONE(xx)

#define FOR_ALL_ZONES(xx) \
    DMA_ZONE(xx) DMA32_ZONE(xx) xx##_NORMAL, HIGHMEM_ZONE(xx) xx##_MOVABLE

enum vm_event_item { PGPGIN, PGPGOUT, PSWPIN, PSWPOUT,
        FOR_ALL_ZONES(PGALLOC),
        FOR_ALL_ZONES(ALLOCSTALL),
        FOR_ALL_ZONES(PGSCAN_SKIP),
        PGFREE, PGACTIVATE, PGDEACTIVATE, PGLAZYFREE,
        PGFAULT, PGMAJFAULT,
        PGLAZYFREED,
        PGREFILL,
        PGREUSE,
        PGSTEAL_KSWAPD,
        PGSTEAL_DIRECT,
        PGDEMOTE_KSWAPD,
        PGDEMOTE_DIRECT,
        PGSCAN_KSWAPD,
        PGSCAN_DIRECT,
        PGSCAN_DIRECT_THROTTLE,
        PGSCAN_ANON,
        PGSCAN_FILE,
        PGSTEAL_ANON,
        PGSTEAL_FILE,
        PGINODESTEAL, SLABS_SCANNED, KSWAPD_INODESTEAL,
        KSWAPD_LOW_WMARK_HIT_QUICKLY, KSWAPD_HIGH_WMARK_HIT_QUICKLY,
        PAGEOUTRUN, PGROTATED,
        DROP_PAGECACHE, DROP_SLAB,
        OOM_KILL,
        PGMIGRATE_SUCCESS, PGMIGRATE_FAIL,
        THP_MIGRATION_SUCCESS,
        THP_MIGRATION_FAIL,
        THP_MIGRATION_SPLIT,
        COMPACTMIGRATE_SCANNED, COMPACTFREE_SCANNED,
        COMPACTISOLATED,
        COMPACTSTALL, COMPACTFAIL, COMPACTSUCCESS,
        KCOMPACTD_WAKE,
        KCOMPACTD_MIGRATE_SCANNED, KCOMPACTD_FREE_SCANNED,
        HTLB_BUDDY_PGALLOC, HTLB_BUDDY_PGALLOC_FAIL,
        UNEVICTABLE_PGCULLED,   /* culled to noreclaim list */
        UNEVICTABLE_PGSCANNED,  /* scanned for reclaimability */
        UNEVICTABLE_PGRESCUED,  /* rescued from noreclaim list */
        UNEVICTABLE_PGMLOCKED,
        UNEVICTABLE_PGMUNLOCKED,
        UNEVICTABLE_PGCLEARED,  /* on COW, page truncate */
        UNEVICTABLE_PGSTRANDED, /* unable to isolate on unlock */
        NR_VM_EVENT_ITEMS
};

#endif  /* VM_EVENT_ITEM_H_INCLUDED */


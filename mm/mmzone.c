// SPDX-License-Identifier: GPL-2.0
/*
 * linux/mm/mmzone.c
 *
 * management codes for pgdats, zones and page flags
 */

#include <linux/mm.h>
#include <linux/mmzone.h>

/* Returns the next zone at or below highest_zoneidx in a zonelist */
static inline int zref_in_nodemask(struct zoneref *zref, nodemask_t *nodes)
{
    return 1;
}

struct zoneref *
__next_zones_zonelist(struct zoneref *z,
                      enum zone_type highest_zoneidx,
                      nodemask_t *nodes)
{
    /*
     * Find the next suitable zone to use for the allocation.
     * Only filter based on nodemask if it's set
     */
    if (unlikely(nodes == NULL))
        while (zonelist_zone_idx(z) > highest_zoneidx)
            z++;
    else
        while (zonelist_zone_idx(z) > highest_zoneidx ||
               (z->zone && !zref_in_nodemask(z, nodes)))
            z++;

    return z;
}

struct pglist_data *first_online_pgdat(void)
{
    return NODE_DATA(first_online_node);
}

struct pglist_data *next_online_pgdat(struct pglist_data *pgdat)
{
    int nid = next_online_node(pgdat->node_id);

    if (nid == MAX_NUMNODES)
        return NULL;
    return NODE_DATA(nid);
}

/*
 * next_zone - helper magic for for_each_zone()
 */
struct zone *next_zone(struct zone *zone)
{
    pg_data_t *pgdat = zone->zone_pgdat;

    if (zone < pgdat->node_zones + MAX_NR_ZONES - 1)
        zone++;
    else {
        pgdat = next_online_pgdat(pgdat);
        if (pgdat)
            zone = pgdat->node_zones;
        else
            zone = NULL;
    }
    return zone;
}

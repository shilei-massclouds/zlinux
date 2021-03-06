/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/pagemap.h>
#include <linux/blkdev.h>
#include "../blk.h"

/*
 * add_gd_partition adds a partitions details to the devices partition
 * description.
 */
struct parsed_partitions {
    struct gendisk *disk;
    char name[BDEVNAME_SIZE];
    struct {
        sector_t from;
        sector_t size;
        int flags;
        bool has_info;
        struct partition_meta_info info;
    } *parts;
    int next;
    int limit;
    bool access_beyond_eod;
    char *pp_buf;
};

typedef struct {
    struct page *v;
} Sector;

int efi_partition(struct parsed_partitions *state);
int msdos_partition(struct parsed_partitions *state);

void *read_part_sector(struct parsed_partitions *state, sector_t n, Sector *p);
static inline void put_dev_sector(Sector p)
{
    put_page(p.v);
}

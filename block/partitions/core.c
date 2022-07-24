// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 1991-1998  Linus Torvalds
 * Re-organised Feb 1998 Russell King
 * Copyright (C) 2020 Christoph Hellwig
 */
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/vmalloc.h>
#include <linux/blkdev.h>
#if 0
#include <linux/blktrace_api.h>
#include <linux/raid/detect.h>
#endif
#include "check.h"

static int (*check_part[])(struct parsed_partitions *) = {
    efi_partition,      /* this must come before msdos */
    msdos_partition,
    NULL
};

static void delete_partition(struct block_device *part)
{
#if 0
    fsync_bdev(part);
    __invalidate_device(part, true);
#endif

    xa_erase(&part->bd_disk->part_tbl, part->bd_partno);
    kobject_put(part->bd_holder_dir);
    device_del(&part->bd_device);

    /*
     * Remove the block device from the inode hash, so that it cannot be
     * looked up any more even when openers still hold references.
     */
    remove_inode_hash(part->bd_inode);

    put_device(&part->bd_device);
}

void blk_drop_partitions(struct gendisk *disk)
{
    struct block_device *part;
    unsigned long idx;

    xa_for_each_start(&disk->part_tbl, idx, part, 1)
        delete_partition(part);
}

static struct parsed_partitions *allocate_partitions(struct gendisk *hd)
{
    struct parsed_partitions *state;
    int nr = DISK_MAX_PARTS;

    state = kzalloc(sizeof(*state), GFP_KERNEL);
    if (!state)
        return NULL;

    state->parts = vzalloc(array_size(nr, sizeof(state->parts[0])));
    if (!state->parts) {
        kfree(state);
        return NULL;
    }

    state->limit = nr;

    return state;
}

static void free_partitions(struct parsed_partitions *state)
{
    vfree(state->parts);
    kfree(state);
}

static struct parsed_partitions *check_partition(struct gendisk *hd)
{
    struct parsed_partitions *state;
    int i, res, err;

    state = allocate_partitions(hd);
    if (!state)
        return NULL;
    state->pp_buf = (char *)__get_free_page(GFP_KERNEL);
    if (!state->pp_buf) {
        free_partitions(state);
        return NULL;
    }
    state->pp_buf[0] = '\0';

    state->disk = hd;
    snprintf(state->name, BDEVNAME_SIZE, "%s", hd->disk_name);
    snprintf(state->pp_buf, PAGE_SIZE, " %s:", state->name);
    if (isdigit(state->name[strlen(state->name)-1]))
        sprintf(state->name, "p");

    i = res = err = 0;
    while (!res && check_part[i]) {
        memset(state->parts, 0, state->limit * sizeof(state->parts[0]));
        res = check_part[i++](state);
        if (res < 0) {
            /*
             * We have hit an I/O error which we don't report now.
             * But record it, and let the others do their job.
             */
            err = res;
            res = 0;
        }

    }

    panic("%s: END!\n", __func__);
}

static int blk_add_partitions(struct gendisk *disk)
{
    struct parsed_partitions *state;
    int ret = -EAGAIN, p;

    if (disk->flags & GENHD_FL_NO_PART)
        return 0;

    state = check_partition(disk);
    if (!state)
        return 0;

    panic("%s: END!\n", __func__);
}

int bdev_disk_changed(struct gendisk *disk, bool invalidate)
{
    int ret = 0;

    if (!disk_live(disk))
        return -ENXIO;

 rescan:
    if (disk->open_partitions)
        return -EBUSY;
    sync_blockdev(disk->part0);
    invalidate_bdev(disk->part0);
    blk_drop_partitions(disk);

    clear_bit(GD_NEED_PART_SCAN, &disk->state);

    /*
     * Historically we only set the capacity to zero for devices that
     * support partitions (independ of actually having partitions created).
     * Doing that is rather inconsistent, but changing it broke legacy
     * udisks polling for legacy ide-cdrom devices.  Use the crude check
     * below to get the sane behavior for most device while not breaking
     * userspace for this particular setup.
     */
    if (invalidate) {
        if (!(disk->flags & GENHD_FL_NO_PART) ||
            !(disk->flags & GENHD_FL_REMOVABLE))
            set_capacity(disk, 0);
    }

    if (get_capacity(disk)) {
        ret = blk_add_partitions(disk);
        if (ret == -EAGAIN)
            goto rescan;
    } else if (invalidate) {
#if 0
        /*
         * Tell userspace that the media / partition table may have
         * changed.
         */
        kobject_uevent(&disk_to_dev(disk)->kobj, KOBJ_CHANGE);
#endif
        panic("%s: get_capacity == 0!\n", __func__);
    }

    panic("%s: END!\n", __func__);
    return ret;
}
EXPORT_SYMBOL_GPL(bdev_disk_changed);

void *read_part_sector(struct parsed_partitions *state, sector_t n, Sector *p)
{
    struct address_space *mapping = state->disk->part0->bd_inode->i_mapping;
    struct page *page;

    if (n >= get_capacity(state->disk)) {
        state->access_beyond_eod = true;
        return NULL;
    }

    page = read_mapping_page(mapping, (pgoff_t)(n >> (PAGE_SHIFT - 9)), NULL);
    if (IS_ERR(page))
        goto out;
    if (PageError(page))
        goto out_put_page;

    panic("%s: END!\n", __func__);
    p->v = page;
    return (unsigned char *)page_address(page) +
        ((n & ((1 << (PAGE_SHIFT - 9)) - 1)) << SECTOR_SHIFT);

 out_put_page:
    put_page(page);
 out:
    p->v = NULL;
    return NULL;
}

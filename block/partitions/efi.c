// SPDX-License-Identifier: GPL-2.0-or-later
/************************************************************
 * EFI GUID Partition Table handling
 *
 * http://www.uefi.org/specs/
 * http://www.intel.com/technology/efi/
 *
 * efi.[ch] by Matt Domsch <Matt_Domsch@dell.com>
 *   Copyright 2000,2001,2002,2004 Dell Inc.
 *
 ************************************************************/
#include <linux/kernel.h>
//#include <linux/crc32.h>
#include <linux/ctype.h>
#include <linux/math64.h>
#include <linux/slab.h>
#include "check.h"
#include "efi.h"

/* This allows a kernel command line option 'gpt' to override
 * the test for invalid PMBR.  Not __initdata because reloading
 * the partition tables happens after init too.
 */
static int force_gpt;

/**
 * last_lba(): return number of last logical block of device
 * @disk: block device
 *
 * Description: Returns last LBA value on success, 0 on error.
 * This is stored (by sd and ide-geometry) in
 *  the part[0] entry for this disk, and is the number of
 *  physical sectors available on the disk.
 */
static u64 last_lba(struct gendisk *disk)
{
    return div_u64(bdev_nr_bytes(disk->part0),
                   queue_logical_block_size(disk->queue)) - 1ULL;
}

/**
 * is_pmbr_valid(): test Protective MBR for validity
 * @mbr: pointer to a legacy mbr structure
 * @total_sectors: amount of sectors in the device
 *
 * Description: Checks for a valid protective or hybrid
 * master boot record (MBR). The validity of a pMBR depends
 * on all of the following properties:
 *  1) MSDOS signature is in the last two bytes of the MBR
 *  2) One partition of type 0xEE is found
 *
 * In addition, a hybrid MBR will have up to three additional
 * primary partitions, which point to the same space that's
 * marked out by up to three GPT partitions.
 *
 * Returns 0 upon invalid MBR, or GPT_MBR_PROTECTIVE or
 * GPT_MBR_HYBRID depending on the device layout.
 */
static int is_pmbr_valid(legacy_mbr *mbr, sector_t total_sectors)
{
    panic("%s: END!\n", __func__);
}

/**
 * read_lba(): Read bytes from disk, starting at given LBA
 * @state: disk parsed partitions
 * @lba: the Logical Block Address of the partition table
 * @buffer: destination buffer
 * @count: bytes to read
 *
 * Description: Reads @count bytes from @state->disk into @buffer.
 * Returns number of bytes read on success, 0 on error.
 */
static size_t read_lba(struct parsed_partitions *state,
                       u64 lba, u8 *buffer, size_t count)
{
    size_t totalreadcount = 0;
    sector_t n = lba * (queue_logical_block_size(state->disk->queue) / 512);

    if (!buffer || lba > last_lba(state->disk))
        return 0;

    while (count) {
        int copied = 512;
        Sector sect;
        unsigned char *data = read_part_sector(state, n++, &sect);
        if (!data)
            break;

        panic("%s: count(%d) !\n", __func__, count);
    }

    panic("%s: END!\n", __func__);
}

/**
 * find_valid_gpt() - Search disk for valid GPT headers and PTEs
 * @state: disk parsed partitions
 * @gpt: GPT header ptr, filled on return.
 * @ptes: PTEs ptr, filled on return.
 *
 * Description: Returns 1 if valid, 0 on error.
 * If valid, returns pointers to newly allocated GPT header and PTEs.
 * Validity depends on PMBR being valid (or being overridden by the
 * 'gpt' kernel command line option) and finding either the Primary
 * GPT header and PTEs valid, or the Alternate GPT header and PTEs
 * valid.  If the Primary GPT header is not valid, the Alternate GPT header
 * is not checked unless the 'gpt' kernel command line option is passed.
 * This protects against devices which misreport their size, and forces
 * the user to decide to use the Alternate GPT.
 */
static int find_valid_gpt(struct parsed_partitions *state, gpt_header **gpt,
                          gpt_entry **ptes)
{
    int good_pgpt = 0, good_agpt = 0, good_pmbr = 0;
    gpt_header *pgpt = NULL, *agpt = NULL;
    gpt_entry *pptes = NULL, *aptes = NULL;
    legacy_mbr *legacymbr;
    struct gendisk *disk = state->disk;
    const struct block_device_operations *fops = disk->fops;
    sector_t total_sectors = get_capacity(state->disk);
    u64 lastlba;

    if (!ptes)
        return 0;

    lastlba = last_lba(state->disk);
    if (!force_gpt) {
        /* This will be added to the EFI Spec. per Intel after v1.02. */
        legacymbr = kzalloc(sizeof(*legacymbr), GFP_KERNEL);
        if (!legacymbr)
            goto fail;

        read_lba(state, 0, (u8 *)legacymbr, sizeof(*legacymbr));
        good_pmbr = is_pmbr_valid(legacymbr, total_sectors);
        kfree(legacymbr);

        if (!good_pmbr)
            goto fail;

        pr_info("Device has a %s MBR\n",
                good_pmbr == GPT_MBR_PROTECTIVE ? "protective" : "hybrid");
    }

    panic("%s: END!\n", __func__);

 fail:
    kfree(pgpt);
    kfree(agpt);
    kfree(pptes);
    kfree(aptes);
    *gpt = NULL;
    *ptes = NULL;
    return 0;
}


/**
 * efi_partition - scan for GPT partitions
 * @state: disk parsed partitions
 *
 * Description: called from check.c, if the disk contains GPT
 * partitions, sets up partition entries in the kernel.
 *
 * If the first block on the disk is a legacy MBR,
 * it will get handled by msdos_partition().
 * If it's a Protective MBR, we'll handle it here.
 *
 * We do not create a Linux partition for GPT, but
 * only for the actual data partitions.
 * Returns:
 * -1 if unable to read the partition table
 *  0 if this isn't our partition table
 *  1 if successful
 *
 */
int efi_partition(struct parsed_partitions *state)
{
    gpt_header *gpt = NULL;
    gpt_entry *ptes = NULL;
    u32 i;
    unsigned ssz = queue_logical_block_size(state->disk->queue) / 512;

    if (!find_valid_gpt(state, &gpt, &ptes) || !gpt || !ptes) {
        kfree(gpt);
        kfree(ptes);
        return 0;
    }

    pr_info("GUID Partition Table is valid!  Yea!\n");

    panic("%s: ssz(%u) END!\n", __func__, ssz);
}

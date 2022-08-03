// SPDX-License-Identifier: GPL-2.0
/*
 *  fs/partitions/msdos.c
 *
 *  Code extracted from drivers/block/genhd.c
 *  Copyright (C) 1991-1998  Linus Torvalds
 *
 *  Thanks to Branko Lankester, lankeste@fwi.uva.nl, who found a bug
 *  in the early extended-partition checks and added DM partitions
 *
 *  Support for DiskManager v6.0x added by Mark Lord,
 *  with information provided by OnTrack.  This now works for linux fdisk
 *  and LILO, as well as loadlin and bootln.  Note that disks other than
 *  /dev/hda *must* have a "DOS" type 0x51 partition in the first slot (hda1).
 *
 *  More flexible handling of extended partitions - aeb, 950831
 *
 *  Check partition table on IDE disks for common CHS translations
 *
 *  Re-organised Feb 1998 Russell King
 *
 *  BSD disklabel support by Yossi Gottlieb <yogo@math.tau.ac.il>
 *  updated by Marc Espie <Marc.Espie@openbsd.org>
 *
 *  Unixware slices support by Andrzej Krzysztofowicz <ankry@mif.pg.gda.pl>
 *  and Krzysztof G. Baranowski <kgb@knm.org.pl>
 */
#if 0
#include <linux/msdos_fs.h>
#include <linux/msdos_partition.h>
#endif

#include "check.h"
#include "efi.h"

/*
 * Many architectures don't like unaligned accesses, while
 * the nr_sects and start_sect partition table entries are
 * at a 2 (mod 4) address.
 */
//#include <asm/unaligned.h>

/* Value is EBCDIC 'IBMA' */
#define AIX_LABEL_MAGIC1    0xC9
#define AIX_LABEL_MAGIC2    0xC2
#define AIX_LABEL_MAGIC3    0xD4
#define AIX_LABEL_MAGIC4    0xC1

#define MSDOS_LABEL_MAGIC1  0x55
#define MSDOS_LABEL_MAGIC2  0xAA

static inline int
msdos_magic_present(unsigned char *p)
{
    printk("%s: %x %x\n", __func__, p[0], p[1]);
    return (p[0] == MSDOS_LABEL_MAGIC1 && p[1] == MSDOS_LABEL_MAGIC2);
}

static int aix_magic_present(struct parsed_partitions *state, unsigned char *p)
{
    if (!(p[0] == AIX_LABEL_MAGIC1 && p[1] == AIX_LABEL_MAGIC2 &&
          p[2] == AIX_LABEL_MAGIC3 && p[3] == AIX_LABEL_MAGIC4))
        return 0;

    panic("%s: END!\n", __func__);
}

int msdos_partition(struct parsed_partitions *state)
{
    sector_t sector_size;
    Sector sect;
    unsigned char *data;
    struct msdos_partition *p;
    struct fat_boot_sector *fb;
    int slot;
    u32 disksig;

    sector_size = queue_logical_block_size(state->disk->queue) / 512;
    data = read_part_sector(state, 0, &sect);
    if (!data)
        return -1;

    /*
     * Note order! (some AIX disks, e.g. unbootable kind,
     * have no MSDOS 55aa)
     */
    if (aix_magic_present(state, data)) {
        put_dev_sector(sect);
        strlcat(state->pp_buf, " [AIX]", PAGE_SIZE);
        return 0;
    }

    if (!msdos_magic_present(data + 510)) {
        put_dev_sector(sect);
        return 0;
    }

    panic("%s: END!\n", __func__);
}

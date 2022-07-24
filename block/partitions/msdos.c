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
//#include "efi.h"

/*
 * Many architectures don't like unaligned accesses, while
 * the nr_sects and start_sect partition table entries are
 * at a 2 (mod 4) address.
 */
//#include <asm/unaligned.h>

int msdos_partition(struct parsed_partitions *state)
{
    panic("%s: END!\n", __func__);
}

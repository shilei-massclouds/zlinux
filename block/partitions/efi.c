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
//#include "efi.h"

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
    panic("%s: END!\n", __func__);
}

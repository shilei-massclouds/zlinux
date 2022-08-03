/* SPDX-License-Identifier: GPL-2.0-or-later */
/************************************************************
 * EFI GUID Partition Table
 * Per Intel EFI Specification v1.02
 * http://developer.intel.com/technology/efi/efi.htm
 *
 * By Matt Domsch <Matt_Domsch@dell.com>  Fri Sep 22 22:15:56 CDT 2000
 *   Copyright 2000,2001 Dell Inc.
 ************************************************************/

#ifndef FS_PART_EFI_H_INCLUDED
#define FS_PART_EFI_H_INCLUDED

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/string.h>
#include <linux/efi.h>
#include <linux/compiler.h>

#define MSDOS_MBR_SIGNATURE     0xaa55
#define EFI_PMBR_OSTYPE_EFI     0xEF
#define EFI_PMBR_OSTYPE_EFI_GPT 0xEE

#define GPT_MBR_PROTECTIVE  1
#define GPT_MBR_HYBRID      2

typedef struct _gpt_header {
    __le64 signature;
    __le32 revision;
    __le32 header_size;
    __le32 header_crc32;
    __le32 reserved1;
    __le64 my_lba;
    __le64 alternate_lba;
    __le64 first_usable_lba;
    __le64 last_usable_lba;
    efi_guid_t disk_guid;
    __le64 partition_entry_lba;
    __le32 num_partition_entries;
    __le32 sizeof_partition_entry;
    __le32 partition_entry_array_crc32;

    /* The rest of the logical block is reserved by UEFI and must be zero.
     * EFI standard handles this by:
     *
     * uint8_t      reserved2[ BlockSize - 92 ];
     */
} __packed gpt_header;

typedef struct _gpt_entry_attributes {
    u64 required_to_function:1;
    u64 reserved:47;
    u64 type_guid_specific:16;
} __packed gpt_entry_attributes;

typedef struct _gpt_entry {
    efi_guid_t partition_type_guid;
    efi_guid_t unique_partition_guid;
    __le64 starting_lba;
    __le64 ending_lba;
    gpt_entry_attributes attributes;
    __le16 partition_name[72/sizeof(__le16)];
} __packed gpt_entry;

typedef struct _gpt_mbr_record {
    u8  boot_indicator; /* unused by EFI, set to 0x80 for bootable */
    u8  start_head;     /* unused by EFI, pt start in CHS */
    u8  start_sector;   /* unused by EFI, pt start in CHS */
    u8  start_track;
    u8  os_type;        /* EFI and legacy non-EFI OS types */
    u8  end_head;       /* unused by EFI, pt end in CHS */
    u8  end_sector;     /* unused by EFI, pt end in CHS */
    u8  end_track;      /* unused by EFI, pt end in CHS */
    __le32  starting_lba;   /* used by EFI - start addr of the on disk pt */
    __le32  size_in_lba;    /* used by EFI - size of pt in LBA */
} __packed gpt_mbr_record;

typedef struct _legacy_mbr {
    u8 boot_code[440];
    __le32 unique_mbr_signature;
    __le16 unknown;
    gpt_mbr_record partition_record[4];
    __le16 signature;
} __packed legacy_mbr;

#endif /* FS_PART_EFI_H_INCLUDED */

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_EFI_H
#define _LINUX_EFI_H

/*
 * Extensible Firmware Interface
 * Based on 'Extensible Firmware Interface Specification' version 0.9, April 30, 1999
 *
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999, 2002-2003 Hewlett-Packard Co.
 *  David Mosberger-Tang <davidm@hpl.hp.com>
 *  Stephane Eranian <eranian@hpl.hp.com>
 */
#include <linux/init.h>
#include <linux/string.h>
//#include <linux/time.h>
#include <linux/types.h>
#if 0
#include <linux/proc_fs.h>
#include <linux/rtc.h>
#endif
#include <linux/ioport.h>
#include <linux/pfn.h>
#if 0
#include <linux/pstore.h>
#include <linux/range.h>
#include <linux/screen_info.h>
#endif
#include <linux/reboot.h>
#include <linux/uuid.h>

#include <asm/page.h>

/*
 * The UEFI spec and EDK2 reference implementation both define EFI_GUID as
 * struct { u32 a; u16; b; u16 c; u8 d[8]; }; and so the implied alignment
 * is 32 bits not 8 bits like our guid_t. In some cases (i.e., on 32-bit ARM),
 * this means that firmware services invoked by the kernel may assume that
 * efi_guid_t* arguments are 32-bit aligned, and use memory accessors that
 * do not tolerate misalignment. So let's set the minimum alignment to 32 bits.
 *
 * Note that the UEFI spec as well as some comments in the EDK2 code base
 * suggest that EFI_GUID should be 64-bit aligned, but this appears to be
 * a mistake, given that no code seems to exist that actually enforces that
 * or relies on it.
 */
typedef guid_t efi_guid_t __aligned(__alignof__(u32));

#endif /* _LINUX_EFI_H */

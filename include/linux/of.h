/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _LINUX_OF_H
#define _LINUX_OF_H
/*
 * Definitions for talking to the Open Firmware PROM on
 * Power Macintosh and other computers.
 *
 * Copyright (C) 1996-2005 Paul Mackerras.
 *
 * Updates for PPC64 by Peter Bergner & David Engebretsen, IBM Corp.
 * Updates for SPARC64 by David S. Miller
 * Derived from PowerPC and Sparc prom.h files by Stephen Rothwell, IBM Corp.
 */
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/errno.h>
/*
#include <linux/kobject.h>
#include <linux/mod_devicetable.h>
*/
#include <linux/spinlock.h>
/*
#include <linux/topology.h>
#include <linux/notifier.h>
#include <linux/property.h>
*/
#include <linux/list.h>

#include <asm/byteorder.h>
#include <asm/errno.h>

/*
 * OF address retrieval & translation
 */

/* Helper to read a big number; size is in cells (not bytes) */
static inline u64 of_read_number(const __be32 *cell, int size)
{
    u64 r = 0;
    for (; size--; cell++)
        r = (r << 32) | be32_to_cpu(*cell);
    return r;
}

#endif /* _LINUX_OF_H */

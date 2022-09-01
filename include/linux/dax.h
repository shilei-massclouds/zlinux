/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_DAX_H
#define _LINUX_DAX_H

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/radix-tree.h>

typedef unsigned long dax_entry_t;

struct dax_device;
struct gendisk;
struct iomap_ops;
struct iomap_iter;
struct iomap;

static inline bool dax_mapping(struct address_space *mapping)
{
    return mapping->host && IS_DAX(mapping->host);
}

#endif /* _LINUX_DAX_H */

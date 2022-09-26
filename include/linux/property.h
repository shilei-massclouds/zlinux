/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * property.h - Unified device property interface.
 *
 * Copyright (C) 2014, Intel Corporation
 * Authors: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
 *          Mika Westerberg <mika.westerberg@linux.intel.com>
 */

#ifndef _LINUX_PROPERTY_H_
#define _LINUX_PROPERTY_H_

#include <linux/bits.h>
#include <linux/fwnode.h>
#include <linux/types.h>

struct fwnode_handle *fwnode_handle_get(struct fwnode_handle *fwnode);
void fwnode_handle_put(struct fwnode_handle *fwnode);

struct fwnode_handle *fwnode_get_parent(const struct fwnode_handle *fwnode);
struct fwnode_handle *fwnode_get_next_parent( struct fwnode_handle *fwnode);

unsigned int fwnode_count_parents(const struct fwnode_handle *fwn);

struct fwnode_handle *
fwnode_get_nth_parent(struct fwnode_handle *fwn, unsigned int depth);

const char *fwnode_get_name(const struct fwnode_handle *fwnode);
const char *fwnode_get_name_prefix(const struct fwnode_handle *fwnode);

bool is_software_node(const struct fwnode_handle *fwnode);

bool device_property_present(struct device *dev, const char *propname);
int device_property_read_u8_array(struct device *dev,
                                  const char *propname,
                                  u8 *val, size_t nval);
int device_property_read_u16_array(struct device *dev,
                                   const char *propname,
                                   u16 *val, size_t nval);
int device_property_read_u32_array(struct device *dev,
                                   const char *propname,
                                   u32 *val, size_t nval);
int device_property_read_u64_array(struct device *dev,
                                   const char *propname,
                                   u64 *val, size_t nval);
int device_property_read_string_array(struct device *dev,
                                      const char *propname,
                                      const char **val, size_t nval);
int device_property_read_string(struct device *dev,
                                const char *propname,
                                const char **val);
int device_property_match_string(struct device *dev,
                                 const char *propname,
                                 const char *string);

static inline bool device_property_read_bool(struct device *dev,
                         const char *propname)
{
    return device_property_present(dev, propname);
}

struct fwnode_handle *dev_fwnode(struct device *dev);

#endif /* _LINUX_PROPERTY_H_ */

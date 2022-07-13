/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sysfs.h - definitions for the device driver filesystem
 *
 * Copyright (c) 2001,2002 Patrick Mochel
 * Copyright (c) 2004 Silicon Graphics, Inc.
 * Copyright (c) 2007 SUSE Linux Products GmbH
 * Copyright (c) 2007 Tejun Heo <teheo@suse.de>
 *
 * Please see Documentation/filesystems/sysfs.rst for more information.
 */

#ifndef _SYSFS_H_
#define _SYSFS_H_

//#include <linux/kernfs.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/list.h>
//#include <linux/kobject_ns.h>
//#include <linux/stat.h>
#include <linux/atomic.h>

struct kobject;
struct module;
struct bin_attribute;
enum kobj_ns_type;

struct attribute {
    const char *name;
    umode_t mode;
};

struct file;
struct vm_area_struct;
struct address_space;

struct bin_attribute {
};

/**
 * struct attribute_group - data structure used to declare an attribute group.
 * @name:   Optional: Attribute group name
 *      If specified, the attribute group will be created in
 *      a new subdirectory with this name.
 * @is_visible: Optional: Function to return permissions associated with an
 *      attribute of the group. Will be called repeatedly for each
 *      non-binary attribute in the group. Only read/write
 *      permissions as well as SYSFS_PREALLOC are accepted. Must
 *      return 0 if an attribute is not visible. The returned value
 *      will replace static permissions defined in struct attribute.
 * @is_bin_visible:
 *      Optional: Function to return permissions associated with a
 *      binary attribute of the group. Will be called repeatedly
 *      for each binary attribute in the group. Only read/write
 *      permissions as well as SYSFS_PREALLOC are accepted. Must
 *      return 0 if a binary attribute is not visible. The returned
 *      value will replace static permissions defined in
 *      struct bin_attribute.
 * @attrs:  Pointer to NULL terminated list of attributes.
 * @bin_attrs:  Pointer to NULL terminated list of binary attributes.
 *      Either attrs or bin_attrs or both must be provided.
 */
struct attribute_group {
    const char *name;
    umode_t (*is_visible)(struct kobject *, struct attribute *, int);
    umode_t (*is_bin_visible)(struct kobject *, struct bin_attribute *, int);
    struct attribute **attrs;
    struct bin_attribute **bin_attrs;
};

#endif /* _SYSFS_H_ */

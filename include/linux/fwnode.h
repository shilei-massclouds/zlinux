/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * fwnode.h - Firmware device node object handle type definition.
 *
 * Copyright (C) 2015, Intel Corporation
 * Author: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
 */

#ifndef _LINUX_FWNODE_H_
#define _LINUX_FWNODE_H_

#include <linux/types.h>
#include <linux/list.h>
#include <linux/bits.h>
#include <linux/err.h>

#define fwnode_has_op(fwnode, op) \
    ((fwnode) && (fwnode)->ops && (fwnode)->ops->op)

#define fwnode_call_ptr_op(fwnode, op, ...) \
    (fwnode_has_op(fwnode, op) ?            \
     (fwnode)->ops->op(fwnode, ## __VA_ARGS__) : NULL)

#define fwnode_call_void_op(fwnode, op, ...)    \
    do {                                        \
        if (fwnode_has_op(fwnode, op))          \
            (fwnode)->ops->op(fwnode, ## __VA_ARGS__);  \
    } while (false)

struct fwnode_operations;
struct device;

struct fwnode_handle {
    struct fwnode_handle *secondary;
    const struct fwnode_operations *ops;
    struct device *dev;
    struct list_head suppliers;
    struct list_head consumers;
    u8 flags;
};

/**
 * struct fwnode_operations - Operations for fwnode interface
 * @get: Get a reference to an fwnode.
 * @put: Put a reference to an fwnode.
 * @device_is_available: Return true if the device is available.
 * @device_get_match_data: Return the device driver match data.
 * @property_present: Return true if a property is present.
 * @property_read_int_array: Read an array of integer properties. Return zero on
 *               success, a negative error code otherwise.
 * @property_read_string_array: Read an array of string properties. Return zero
 *              on success, a negative error code otherwise.
 * @get_name: Return the name of an fwnode.
 * @get_name_prefix: Get a prefix for a node (for printing purposes).
 * @get_parent: Return the parent of an fwnode.
 * @get_next_child_node: Return the next child node in an iteration.
 * @get_named_child_node: Return a child node with a given name.
 * @get_reference_args: Return a reference pointed to by a property, with args
 * @graph_get_next_endpoint: Return an endpoint node in an iteration.
 * @graph_get_remote_endpoint: Return the remote endpoint node of a local
 *                 endpoint node.
 * @graph_get_port_parent: Return the parent node of a port node.
 * @graph_parse_endpoint: Parse endpoint for port and endpoint id.
 * @add_links:  Create fwnode links to all the suppliers of the fwnode. Return
 *      zero on success, a negative error code otherwise.
 */
struct fwnode_operations {
    struct fwnode_handle *(*get)(struct fwnode_handle *fwnode);
    void (*put)(struct fwnode_handle *fwnode);
    const char *(*get_name)(const struct fwnode_handle *fwnode);
    const char *(*get_name_prefix)(const struct fwnode_handle *fwnode);
    struct fwnode_handle *(*get_parent)(const struct fwnode_handle *fwnode);
};

static inline void
fwnode_init(struct fwnode_handle *fwnode, const struct fwnode_operations *ops)
{
    fwnode->ops = ops;
    INIT_LIST_HEAD(&fwnode->consumers);
    INIT_LIST_HEAD(&fwnode->suppliers);
}

#endif /* _LINUX_FWNODE_H_ */

// SPDX-License-Identifier: GPL-2.0
/*
 * property.c - Unified device property interface.
 *
 * Copyright (C) 2014, Intel Corporation
 * Authors: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
 *          Mika Westerberg <mika.westerberg@linux.intel.com>
 */

#if 0
#include <linux/acpi.h>
#include <linux/of_graph.h>
#include <linux/phy.h>
#endif
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/property.h>
#include <linux/device.h>

struct fwnode_handle *dev_fwnode(struct device *dev)
{
    return dev->of_node ? of_fwnode_handle(dev->of_node) : dev->fwnode;
}
EXPORT_SYMBOL_GPL(dev_fwnode);

/**
 * fwnode_get_parent - Return parent firwmare node
 * @fwnode: Firmware whose parent is retrieved
 *
 * Return parent firmware node of the given node if possible or %NULL if no
 * parent was available.
 */
struct fwnode_handle *fwnode_get_parent(const struct fwnode_handle *fwnode)
{
    return fwnode_call_ptr_op(fwnode, get_parent);
}
EXPORT_SYMBOL_GPL(fwnode_get_parent);

/**
 * fwnode_get_next_parent - Iterate to the node's parent
 * @fwnode: Firmware whose parent is retrieved
 *
 * This is like fwnode_get_parent() except that it drops the refcount
 * on the passed node, making it suitable for iterating through a
 * node's parents.
 *
 * Returns a node pointer with refcount incremented, use
 * fwnode_handle_node() on it when done.
 */
struct fwnode_handle *fwnode_get_next_parent(struct fwnode_handle *fwnode)
{
    struct fwnode_handle *parent = fwnode_get_parent(fwnode);

    fwnode_handle_put(fwnode);

    return parent;
}
EXPORT_SYMBOL_GPL(fwnode_get_next_parent);

/**
 * fwnode_count_parents - Return the number of parents a node has
 * @fwnode: The node the parents of which are to be counted
 *
 * Returns the number of parents a node has.
 */
unsigned int fwnode_count_parents(const struct fwnode_handle *fwnode)
{
    struct fwnode_handle *__fwnode;
    unsigned int count;

    __fwnode = fwnode_get_parent(fwnode);

    for (count = 0; __fwnode; count++)
        __fwnode = fwnode_get_next_parent(__fwnode);

    return count;
}
EXPORT_SYMBOL_GPL(fwnode_count_parents);

/**
 * fwnode_handle_get - Obtain a reference to a device node
 * @fwnode: Pointer to the device node to obtain the reference to.
 *
 * Returns the fwnode handle.
 */
struct fwnode_handle *fwnode_handle_get(struct fwnode_handle *fwnode)
{
    if (!fwnode_has_op(fwnode, get))
        return fwnode;

    return fwnode_call_ptr_op(fwnode, get);
}
EXPORT_SYMBOL_GPL(fwnode_handle_get);

/**
 * fwnode_handle_put - Drop reference to a device node
 * @fwnode: Pointer to the device node to drop the reference to.
 *
 * This has to be used when terminating device_for_each_child_node() iteration
 * with break or return to prevent stale device node references from being left
 * behind.
 */
void fwnode_handle_put(struct fwnode_handle *fwnode)
{
    fwnode_call_void_op(fwnode, put);
}
EXPORT_SYMBOL_GPL(fwnode_handle_put);

/**
 * fwnode_get_nth_parent - Return an nth parent of a node
 * @fwnode: The node the parent of which is requested
 * @depth: Distance of the parent from the node
 *
 * Returns the nth parent of a node. If there is no parent at the requested
 * @depth, %NULL is returned. If @depth is 0, the functionality is equivalent to
 * fwnode_handle_get(). For @depth == 1, it is fwnode_get_parent() and so on.
 *
 * The caller is responsible for calling fwnode_handle_put() for the returned
 * node.
 */
struct fwnode_handle *fwnode_get_nth_parent(struct fwnode_handle *fwnode,
                                            unsigned int depth)
{
    unsigned int i;

    fwnode_handle_get(fwnode);

    for (i = 0; i < depth && fwnode; i++)
        fwnode = fwnode_get_next_parent(fwnode);

    return fwnode;
}
EXPORT_SYMBOL_GPL(fwnode_get_nth_parent);

/**
 * fwnode_get_name - Return the name of a node
 * @fwnode: The firmware node
 *
 * Returns a pointer to the node name.
 */
const char *fwnode_get_name(const struct fwnode_handle *fwnode)
{
    return fwnode_call_ptr_op(fwnode, get_name);
}
EXPORT_SYMBOL_GPL(fwnode_get_name);

/**
 * fwnode_get_name_prefix - Return the prefix of node for printing purposes
 * @fwnode: The firmware node
 *
 * Returns the prefix of a node, intended to be printed right before the node.
 * The prefix works also as a separator between the nodes.
 */
const char *fwnode_get_name_prefix(const struct fwnode_handle *fwnode)
{
    return fwnode_call_ptr_op(fwnode, get_name_prefix);
}

static int
fwnode_property_read_int_array(const struct fwnode_handle *fwnode,
                               const char *propname,
                               unsigned int elem_size, void *val,
                               size_t nval)
{
    int ret;

    ret = fwnode_call_int_op(fwnode, property_read_int_array, propname,
                             elem_size, val, nval);
    if (ret == -EINVAL && !IS_ERR_OR_NULL(fwnode) &&
        !IS_ERR_OR_NULL(fwnode->secondary))
        ret = fwnode_call_int_op(fwnode->secondary,
                                 property_read_int_array, propname,
                                 elem_size, val, nval);

    return ret;
}

/**
 * fwnode_property_read_u32_array - return a u32 array property of firmware node
 * @fwnode: Firmware node to get the property of
 * @propname: Name of the property
 * @val: The values are stored here or %NULL to return the number of values
 * @nval: Size of the @val array
 *
 * Read an array of u32 properties with @propname from @fwnode store them to
 * @val if found.
 *
 * Return: number of values if @val was %NULL,
 *         %0 if the property was found (success),
 *     %-EINVAL if given arguments are not valid,
 *     %-ENODATA if the property does not have a value,
 *     %-EPROTO if the property is not an array of numbers,
 *     %-EOVERFLOW if the size of the property is not as expected,
 *     %-ENXIO if no suitable firmware interface is present.
 */
int fwnode_property_read_u32_array(const struct fwnode_handle *fwnode,
                                   const char *propname, u32 *val,
                                   size_t nval)
{
    return fwnode_property_read_int_array(fwnode, propname, sizeof(u32),
                                          val, nval);
}
EXPORT_SYMBOL_GPL(fwnode_property_read_u32_array);

/**
 * device_property_read_u32_array - return a u32 array property of a device
 * @dev: Device to get the property of
 * @propname: Name of the property
 * @val: The values are stored here or %NULL to return the number of values
 * @nval: Size of the @val array
 *
 * Function reads an array of u32 properties with @propname from the device
 * firmware description and stores them to @val if found.
 *
 * Return: number of values if @val was %NULL,
 *         %0 if the property was found (success),
 *     %-EINVAL if given arguments are not valid,
 *     %-ENODATA if the property does not have a value,
 *     %-EPROTO if the property is not an array of numbers,
 *     %-EOVERFLOW if the size of the property is not as expected.
 *     %-ENXIO if no suitable firmware interface is present.
 */
int device_property_read_u32_array(struct device *dev,
                                   const char *propname,
                                   u32 *val, size_t nval)
{
    return fwnode_property_read_u32_array(dev_fwnode(dev), propname,
                                          val, nval);
}
EXPORT_SYMBOL_GPL(device_property_read_u32_array);

/**
 * fwnode_property_present - check if a property of a firmware node is present
 * @fwnode: Firmware node whose property to check
 * @propname: Name of the property
 */
bool fwnode_property_present(const struct fwnode_handle *fwnode,
                             const char *propname)
{
    bool ret;

    ret = fwnode_call_bool_op(fwnode, property_present, propname);
    if (ret == false && !IS_ERR_OR_NULL(fwnode) &&
        !IS_ERR_OR_NULL(fwnode->secondary))
        ret = fwnode_call_bool_op(fwnode->secondary, property_present,
                                  propname);
    return ret;
}
EXPORT_SYMBOL_GPL(fwnode_property_present);

/**
 * device_property_present - check if a property of a device is present
 * @dev: Device whose property is being checked
 * @propname: Name of the property
 *
 * Check if property @propname is present in the device firmware description.
 */
bool device_property_present(struct device *dev, const char *propname)
{
    return fwnode_property_present(dev_fwnode(dev), propname);
}
EXPORT_SYMBOL_GPL(device_property_present);

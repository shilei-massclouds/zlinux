// SPDX-License-Identifier: GPL-2.0+
/*
 * drivers/of/property.c - Procedures for accessing and interpreting
 *             Devicetree properties and graphs.
 *
 * Initially created by copying procedures from drivers/of/base.c. This
 * file contains the OF property as well as the OF graph interface
 * functions.
 *
 * Paul Mackerras   August 1996.
 * Copyright (C) 1996-2005 Paul Mackerras.
 *
 *  Adapted for 64bit PowerPC by Dave Engebretsen and Peter Bergner.
 *    {engebret|bergner}@us.ibm.com
 *
 *  Adapted for sparc and sparc64 by David S. Miller davem@davemloft.net
 *
 *  Reconsolidated from arch/x/kernel/prom.c by Stephen Rothwell and
 *  Grant Likely.
 */

#define pr_fmt(fmt) "OF: " fmt

#include <linux/of.h>
#include <linux/of_device.h>
//#include <linux/of_graph.h>
#include <linux/of_irq.h>
#include <linux/string.h>
#include <linux/moduleparam.h>
#include <linux/err.h>

#include "of_private.h"

int of_property_read_string(const struct device_node *np,
                            const char *propname,
                            const char **out_string)
{
    const struct property *prop = of_find_property(np, propname, NULL);
    if (!prop)
        return -EINVAL;
    if (!prop->value)
        return -ENODATA;
    if (strnlen(prop->value, prop->length) >= prop->length)
        return -EILSEQ;
    *out_string = prop->value;
    return 0;
}
EXPORT_SYMBOL_GPL(of_property_read_string);

const char *of_prop_next_string(struct property *prop, const char *cur)
{
    const void *curv = cur;

    if (!prop)
        return NULL;

    if (!cur)
        return prop->value;

    curv += strlen(cur) + 1;
    if (curv >= prop->value + prop->length)
        return NULL;

    return curv;
}
EXPORT_SYMBOL_GPL(of_prop_next_string);

/**
 * of_find_property_value_of_size
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @min:    minimum allowed length of property value
 * @max:    maximum allowed length of property value (0 means unlimited)
 * @len:    if !=NULL, actual length is written to here
 *
 * Search for a property in a device node and valid the requested size.
 *
 * Return: The property value on success, -EINVAL if the property does not
 * exist, -ENODATA if property does not have a value, and -EOVERFLOW if the
 * property data is too small or too large.
 *
 */
static void *
of_find_property_value_of_size(const struct device_node *np,
                               const char *propname, u32 min, u32 max,
                               size_t *len)
{
    struct property *prop = of_find_property(np, propname, NULL);

    if (!prop)
        return ERR_PTR(-EINVAL);
    if (!prop->value)
        return ERR_PTR(-ENODATA);
    if (prop->length < min)
        return ERR_PTR(-EOVERFLOW);
    if (max && prop->length > max)
        return ERR_PTR(-EOVERFLOW);

    if (len)
        *len = prop->length;

    return prop->value;
}

/**
 * of_property_read_variable_u32_array - Find and read an array of 32 bit
 * integers from a property, with bounds on the minimum and maximum array size.
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_values: pointer to return found values.
 * @sz_min: minimum number of array elements to read
 * @sz_max: maximum number of array elements to read, if zero there is no
 *      upper limit on the number of elements in the dts entry but only
 *      sz_min will be read.
 *
 * Search for a property in a device node and read 32-bit value(s) from
 * it.
 *
 * Return: The number of elements read on success, -EINVAL if the property
 * does not exist, -ENODATA if property does not have a value, and -EOVERFLOW
 * if the property data is smaller than sz_min or longer than sz_max.
 *
 * The out_values is modified only if a valid u32 value can be decoded.
 */
int of_property_read_variable_u32_array(const struct device_node *np,
                                        const char *propname, u32 *out_values,
                                        size_t sz_min, size_t sz_max)
{
    size_t sz, count;
    const __be32 *val;
    val = of_find_property_value_of_size(np, propname,
                                         (sz_min * sizeof(*out_values)),
                                         (sz_max * sizeof(*out_values)),
                                         &sz);

    if (IS_ERR(val))
        return PTR_ERR(val);

    if (!sz_max)
        sz = sz_min;
    else
        sz /= sizeof(*out_values);

    count = sz;
    while (count--)
        *out_values++ = be32_to_cpup(val++);

    return sz;
}
EXPORT_SYMBOL_GPL(of_property_read_variable_u32_array);

/**
 * of_property_read_string_helper() - Utility helper for parsing string properties
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_strs:   output array of string pointers.
 * @sz:     number of array elements to read.
 * @skip:   Number of strings to skip over at beginning of list.
 *
 * Don't call this function directly. It is a utility helper for the
 * of_property_read_string*() family of functions.
 */
int of_property_read_string_helper(const struct device_node *np,
                   const char *propname, const char **out_strs,
                   size_t sz, int skip)
{
    const struct property *prop = of_find_property(np, propname, NULL);
    int l = 0, i = 0;
    const char *p, *end;

    if (!prop)
        return -EINVAL;
    if (!prop->value)
        return -ENODATA;
    p = prop->value;
    end = p + prop->length;

    for (i = 0; p < end && (!out_strs || i < skip + sz); i++, p += l) {
        l = strnlen(p, end - p) + 1;
        if (p + l > end)
            return -EILSEQ;
        if (out_strs && i >= skip)
            *out_strs++ = p;
    }
    i -= skip;
    return i <= 0 ? -ENODATA : i;
}
EXPORT_SYMBOL_GPL(of_property_read_string_helper);

static struct fwnode_handle *
of_fwnode_get_parent(const struct fwnode_handle *fwnode)
{
    return of_fwnode_handle(of_get_parent(to_of_node(fwnode)));
}

static struct fwnode_handle *of_fwnode_get(struct fwnode_handle *fwnode)
{
    return of_fwnode_handle(of_node_get(to_of_node(fwnode)));
}

static void of_fwnode_put(struct fwnode_handle *fwnode)
{
    of_node_put(to_of_node(fwnode));
}

static const char *of_fwnode_get_name(const struct fwnode_handle *fwnode)
{
    return kbasename(to_of_node(fwnode)->full_name);
}

static const char *of_fwnode_get_name_prefix(const struct fwnode_handle *fwnode)
{
    /* Root needs no prefix here (its name is "/"). */
    if (!to_of_node(fwnode)->parent)
        return "";

    return "/";
}

static bool
of_fwnode_device_is_available(const struct fwnode_handle *fwnode)
{
    return of_device_is_available(to_of_node(fwnode));
}

static const void *
of_fwnode_device_get_match_data(const struct fwnode_handle *fwnode,
                                const struct device *dev)
{
    return of_device_get_match_data(dev);
}

static bool
of_fwnode_property_present(const struct fwnode_handle *fwnode,
                           const char *propname)
{
    return of_property_read_bool(to_of_node(fwnode), propname);
}

/**
 * of_property_count_elems_of_size - Count the number of elements in a property
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @elem_size:  size of the individual element
 *
 * Search for a property in a device node and count the number of elements of
 * size elem_size in it.
 *
 * Return: The number of elements on sucess, -EINVAL if the property does not
 * exist or its length does not match a multiple of elem_size and -ENODATA if
 * the property does not have a value.
 */
int of_property_count_elems_of_size(const struct device_node *np,
                                    const char *propname, int elem_size)
{
    struct property *prop = of_find_property(np, propname, NULL);

    if (!prop)
        return -EINVAL;
    if (!prop->value)
        return -ENODATA;

    if (prop->length % elem_size != 0) {
        pr_err("size of %s in node %pOF is not a multiple of %d\n",
               propname, np, elem_size);
        return -EINVAL;
    }

    return prop->length / elem_size;
}
EXPORT_SYMBOL_GPL(of_property_count_elems_of_size);

static int
of_fwnode_property_read_int_array(const struct fwnode_handle *fwnode,
                                  const char *propname,
                                  unsigned int elem_size, void *val,
                                  size_t nval)
{
    const struct device_node *node = to_of_node(fwnode);

    if (!val)
        return of_property_count_elems_of_size(node, propname,
                                               elem_size);

    switch (elem_size) {
    case sizeof(u8):
        return of_property_read_u8_array(node, propname, val, nval);
    case sizeof(u16):
        return of_property_read_u16_array(node, propname, val, nval);
    case sizeof(u32):
        return of_property_read_u32_array(node, propname, val, nval);
    case sizeof(u64):
        return of_property_read_u64_array(node, propname, val, nval);
    }

    return -ENXIO;
}

static int
of_fwnode_property_read_string_array(const struct fwnode_handle *fwnode,
                     const char *propname, const char **val,
                     size_t nval)
{
    const struct device_node *node = to_of_node(fwnode);

    return val ?
        of_property_read_string_array(node, propname, val, nval) :
        of_property_count_strings(node, propname);
}

static struct fwnode_handle *
of_fwnode_get_next_child_node(const struct fwnode_handle *fwnode,
                  struct fwnode_handle *child)
{
    return of_fwnode_handle(of_get_next_available_child(to_of_node(fwnode),
                                to_of_node(child)));
}

static struct fwnode_handle *
of_fwnode_get_named_child_node(const struct fwnode_handle *fwnode,
                   const char *childname)
{
    const struct device_node *node = to_of_node(fwnode);
    struct device_node *child;

    for_each_available_child_of_node(node, child)
        if (of_node_name_eq(child, childname))
            return of_fwnode_handle(child);

    return NULL;
}

static int
of_fwnode_get_reference_args(const struct fwnode_handle *fwnode,
                 const char *prop, const char *nargs_prop,
                 unsigned int nargs, unsigned int index,
                 struct fwnode_reference_args *args)
{
    panic("%s: END!\n", __func__);
}

/**
 * of_graph_get_next_endpoint() - get next endpoint node
 * @parent: pointer to the parent device node
 * @prev: previous endpoint node, or NULL to get first
 *
 * Return: An 'endpoint' node pointer with refcount incremented. Refcount
 * of the passed @prev node is decremented.
 */
struct device_node *of_graph_get_next_endpoint(const struct device_node *parent,
                    struct device_node *prev)
{
    panic("%s: END!\n", __func__);
}

static struct fwnode_handle *
of_fwnode_graph_get_next_endpoint(const struct fwnode_handle *fwnode,
                  struct fwnode_handle *prev)
{
    return of_fwnode_handle(of_graph_get_next_endpoint(to_of_node(fwnode),
                               to_of_node(prev)));
}

/**
 * of_graph_get_remote_endpoint() - get remote endpoint node
 * @node: pointer to a local endpoint device_node
 *
 * Return: Remote endpoint node associated with remote endpoint node linked
 *     to @node. Use of_node_put() on it when done.
 */
struct device_node *of_graph_get_remote_endpoint(const struct device_node *node)
{
    /* Get remote endpoint node. */
    return of_parse_phandle(node, "remote-endpoint", 0);
}
EXPORT_SYMBOL(of_graph_get_remote_endpoint);

static struct fwnode_handle *
of_fwnode_graph_get_remote_endpoint(const struct fwnode_handle *fwnode)
{
    return of_fwnode_handle(
        of_graph_get_remote_endpoint(to_of_node(fwnode)));
}

static struct fwnode_handle *
of_fwnode_graph_get_port_parent(struct fwnode_handle *fwnode)
{
    struct device_node *np;

    /* Get the parent of the port */
    np = of_get_parent(to_of_node(fwnode));
    if (!np)
        return NULL;

    /* Is this the "ports" node? If not, it's the port parent. */
    if (!of_node_name_eq(np, "ports"))
        return of_fwnode_handle(np);

    return of_fwnode_handle(of_get_next_parent(np));
}

static int of_fwnode_graph_parse_endpoint(const struct fwnode_handle *fwnode,
                      struct fwnode_endpoint *endpoint)
{
    const struct device_node *node = to_of_node(fwnode);
    struct device_node *port_node = of_get_parent(node);

    endpoint->local_fwnode = fwnode;

    of_property_read_u32(port_node, "reg", &endpoint->port);
    of_property_read_u32(node, "reg", &endpoint->id);

    of_node_put(port_node);

    return 0;
}

/**
 * of_link_property - Create device links to suppliers listed in a property
 * @con_np: The consumer device tree node which contains the property
 * @prop_name: Name of property to be parsed
 *
 * This function checks if the property @prop_name that is present in the
 * @con_np device tree node is one of the known common device tree bindings
 * that list phandles to suppliers. If @prop_name isn't one, this function
 * doesn't do anything.
 *
 * If @prop_name is one, this function attempts to create fwnode links from the
 * consumer device tree node @con_np to all the suppliers device tree nodes
 * listed in @prop_name.
 *
 * Any failed attempt to create a fwnode link will NOT result in an immediate
 * return.  of_link_property() must create links to all the available supplier
 * device tree nodes even when attempts to create a link to one or more
 * suppliers fail.
 */
static int
of_link_property(struct device_node *con_np, const char *prop_name)
{
    panic("%s: END!\n", __func__);
}

static int of_fwnode_add_links(struct fwnode_handle *fwnode)
{
    struct property *p;
    struct device_node *con_np = to_of_node(fwnode);

    if (!con_np)
        return -EINVAL;

    for_each_property_of_node(con_np, p)
        of_link_property(con_np, p->name);

    return 0;
}

const struct fwnode_operations of_fwnode_ops = {
    .get = of_fwnode_get,
    .put = of_fwnode_put,
    .device_is_available = of_fwnode_device_is_available,
    .device_get_match_data = of_fwnode_device_get_match_data,
    .property_present = of_fwnode_property_present,
    .property_read_int_array = of_fwnode_property_read_int_array,
    .property_read_string_array = of_fwnode_property_read_string_array,
    .get_name = of_fwnode_get_name,
    .get_name_prefix = of_fwnode_get_name_prefix,
    .get_parent = of_fwnode_get_parent,
    .get_next_child_node = of_fwnode_get_next_child_node,
    .get_named_child_node = of_fwnode_get_named_child_node,
    .get_reference_args = of_fwnode_get_reference_args,
    .graph_get_next_endpoint = of_fwnode_graph_get_next_endpoint,
    .graph_get_remote_endpoint = of_fwnode_graph_get_remote_endpoint,
    .graph_get_port_parent = of_fwnode_graph_get_port_parent,
    .graph_parse_endpoint = of_fwnode_graph_parse_endpoint,
    .add_links = of_fwnode_add_links,
};
EXPORT_SYMBOL_GPL(of_fwnode_ops);

/**
 * of_property_read_u32_index - Find and read a u32 from a multi-value property.
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @index:  index of the u32 in the list of values
 * @out_value:  pointer to return value, modified only if no error.
 *
 * Search for a property in a device node and read nth 32-bit value from
 * it.
 *
 * Return: 0 on success, -EINVAL if the property does not exist,
 * -ENODATA if property does not have a value, and -EOVERFLOW if the
 * property data isn't large enough.
 *
 * The out_value is modified only if a valid u32 value can be decoded.
 */
int of_property_read_u32_index(const struct device_node *np,
                               const char *propname,
                               u32 index, u32 *out_value)
{
    const u32 *val =
        of_find_property_value_of_size(np, propname,
                                       ((index + 1) * sizeof(*out_value)),
                                       0,
                                       NULL);

    if (IS_ERR(val))
        return PTR_ERR(val);

    *out_value = be32_to_cpup(((__be32 *)val) + index);
    return 0;
}
EXPORT_SYMBOL_GPL(of_property_read_u32_index);

/**
 * of_property_match_string() - Find string in a list and return index
 * @np: pointer to node containing string list property
 * @propname: string list property name
 * @string: pointer to string to search for in string list
 *
 * This function searches a string list property and returns the index
 * of a specific string value.
 */
int of_property_match_string(const struct device_node *np, const char *propname,
                             const char *string)
{
    const struct property *prop = of_find_property(np, propname, NULL);
    size_t l;
    int i;
    const char *p, *end;

    if (!prop)
        return -EINVAL;
    if (!prop->value)
        return -ENODATA;

    p = prop->value;
    end = p + prop->length;

    for (i = 0; p < end; i++, p += l) {
        l = strnlen(p, end - p) + 1;
        if (p + l > end)
            return -EILSEQ;
        pr_debug("comparing %s with %s\n", string, p);
        if (strcmp(string, p) == 0)
            return i; /* Found it; return index */
    }
    return -ENODATA;
}
EXPORT_SYMBOL_GPL(of_property_match_string);

/**
 * of_property_read_variable_u16_array - Find and read an array of u16 from a
 * property, with bounds on the minimum and maximum array size.
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_values: pointer to found values.
 * @sz_min: minimum number of array elements to read
 * @sz_max: maximum number of array elements to read, if zero there is no
 *      upper limit on the number of elements in the dts entry but only
 *      sz_min will be read.
 *
 * Search for a property in a device node and read 16-bit value(s) from
 * it.
 *
 * dts entry of array should be like:
 *  ``property = /bits/ 16 <0x5000 0x6000 0x7000>;``
 *
 * Return: The number of elements read on success, -EINVAL if the property
 * does not exist, -ENODATA if property does not have a value, and -EOVERFLOW
 * if the property data is smaller than sz_min or longer than sz_max.
 *
 * The out_values is modified only if a valid u16 value can be decoded.
 */
int of_property_read_variable_u16_array(const struct device_node *np,
                    const char *propname, u16 *out_values,
                    size_t sz_min, size_t sz_max)
{
    size_t sz, count;
    const __be16 *val = of_find_property_value_of_size(np, propname,
                        (sz_min * sizeof(*out_values)),
                        (sz_max * sizeof(*out_values)),
                        &sz);

    if (IS_ERR(val))
        return PTR_ERR(val);

    if (!sz_max)
        sz = sz_min;
    else
        sz /= sizeof(*out_values);

    count = sz;
    while (count--)
        *out_values++ = be16_to_cpup(val++);

    return sz;
}
EXPORT_SYMBOL_GPL(of_property_read_variable_u16_array);

/**
 * of_property_read_variable_u8_array - Find and read an array of u8 from a
 * property, with bounds on the minimum and maximum array size.
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_values: pointer to found values.
 * @sz_min: minimum number of array elements to read
 * @sz_max: maximum number of array elements to read, if zero there is no
 *      upper limit on the number of elements in the dts entry but only
 *      sz_min will be read.
 *
 * Search for a property in a device node and read 8-bit value(s) from
 * it.
 *
 * dts entry of array should be like:
 *  ``property = /bits/ 8 <0x50 0x60 0x70>;``
 *
 * Return: The number of elements read on success, -EINVAL if the property
 * does not exist, -ENODATA if property does not have a value, and -EOVERFLOW
 * if the property data is smaller than sz_min or longer than sz_max.
 *
 * The out_values is modified only if a valid u8 value can be decoded.
 */
int of_property_read_variable_u8_array(const struct device_node *np,
                    const char *propname, u8 *out_values,
                    size_t sz_min, size_t sz_max)
{
    size_t sz, count;
    const u8 *val = of_find_property_value_of_size(np, propname,
                        (sz_min * sizeof(*out_values)),
                        (sz_max * sizeof(*out_values)),
                        &sz);

    if (IS_ERR(val))
        return PTR_ERR(val);

    if (!sz_max)
        sz = sz_min;
    else
        sz /= sizeof(*out_values);

    count = sz;
    while (count--)
        *out_values++ = *val++;

    return sz;
}
EXPORT_SYMBOL_GPL(of_property_read_variable_u8_array);

/**
 * of_property_read_variable_u64_array - Find and read an array of 64 bit
 * integers from a property, with bounds on the minimum and maximum array size.
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_values: pointer to found values.
 * @sz_min: minimum number of array elements to read
 * @sz_max: maximum number of array elements to read, if zero there is no
 *      upper limit on the number of elements in the dts entry but only
 *      sz_min will be read.
 *
 * Search for a property in a device node and read 64-bit value(s) from
 * it.
 *
 * Return: The number of elements read on success, -EINVAL if the property
 * does not exist, -ENODATA if property does not have a value, and -EOVERFLOW
 * if the property data is smaller than sz_min or longer than sz_max.
 *
 * The out_values is modified only if a valid u64 value can be decoded.
 */
int of_property_read_variable_u64_array(const struct device_node *np,
                   const char *propname, u64 *out_values,
                   size_t sz_min, size_t sz_max)
{
    size_t sz, count;
    const __be32 *val = of_find_property_value_of_size(np, propname,
                        (sz_min * sizeof(*out_values)),
                        (sz_max * sizeof(*out_values)),
                        &sz);

    if (IS_ERR(val))
        return PTR_ERR(val);

    if (!sz_max)
        sz = sz_min;
    else
        sz /= sizeof(*out_values);

    count = sz;
    while (count--) {
        *out_values++ = of_read_number(val, 2);
        val += 2;
    }

    return sz;
}
EXPORT_SYMBOL_GPL(of_property_read_variable_u64_array);

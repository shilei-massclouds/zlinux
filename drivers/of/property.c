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
//#include <linux/of_device.h>
//#include <linux/of_graph.h>
//#include <linux/of_irq.h>
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

const struct fwnode_operations of_fwnode_ops = {
    .get = of_fwnode_get,
    .put = of_fwnode_put,
    .get_parent = of_fwnode_get_parent,
    .get_name = of_fwnode_get_name,
    .get_name_prefix = of_fwnode_get_name_prefix,
#if 0
    .device_is_available = of_fwnode_device_is_available,
    .device_get_match_data = of_fwnode_device_get_match_data,
    .property_present = of_fwnode_property_present,
    .property_read_int_array = of_fwnode_property_read_int_array,
    .property_read_string_array = of_fwnode_property_read_string_array,
    .get_next_child_node = of_fwnode_get_next_child_node,
    .get_named_child_node = of_fwnode_get_named_child_node,
    .get_reference_args = of_fwnode_get_reference_args,
    .graph_get_next_endpoint = of_fwnode_graph_get_next_endpoint,
    .graph_get_remote_endpoint = of_fwnode_graph_get_remote_endpoint,
    .graph_get_port_parent = of_fwnode_graph_get_port_parent,
    .graph_parse_endpoint = of_fwnode_graph_parse_endpoint,
    .add_links = of_fwnode_add_links,
#endif
};
EXPORT_SYMBOL_GPL(of_fwnode_ops);

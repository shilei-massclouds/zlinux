// SPDX-License-Identifier: GPL-2.0
/*
 * Software nodes for the firmware node framework.
 *
 * Copyright (C) 2018, Intel Corporation
 * Author: Heikki Krogerus <heikki.krogerus@linux.intel.com>
 */

#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/property.h>
#include <linux/slab.h>

#include "base.h"

static const struct fwnode_operations software_node_ops = {
#if 0
    .get = software_node_get,
    .put = software_node_put,
    .property_present = software_node_property_present,
    .property_read_int_array = software_node_read_int_array,
    .property_read_string_array = software_node_read_string_array,
    .get_name = software_node_get_name,
    .get_name_prefix = software_node_get_name_prefix,
    .get_parent = software_node_get_parent,
    .get_next_child_node = software_node_get_next_child,
    .get_named_child_node = software_node_get_named_child_node,
    .get_reference_args = software_node_get_reference_args,
    .graph_get_next_endpoint = software_node_graph_get_next_endpoint,
    .graph_get_remote_endpoint = software_node_graph_get_remote_endpoint,
    .graph_get_port_parent = software_node_graph_get_port_parent,
    .graph_parse_endpoint = software_node_graph_parse_endpoint,
#endif
};

bool is_software_node(const struct fwnode_handle *fwnode)
{
    return !IS_ERR_OR_NULL(fwnode) && fwnode->ops == &software_node_ops;
}
EXPORT_SYMBOL_GPL(is_software_node);

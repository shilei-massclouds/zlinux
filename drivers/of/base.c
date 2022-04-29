// SPDX-License-Identifier: GPL-2.0+
/*
 * Procedures for creating, accessing and interpreting the device tree.
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

//#include <linux/bitmap.h>
#include <linux/console.h>
#include <linux/ctype.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/of.h>
//#include <linux/of_device.h>
//#include <linux/of_graph.h>
#include <linux/spinlock.h>
//#include <linux/slab.h>
#include <linux/string.h>
//#include <linux/proc_fs.h>

#include "of_private.h"

struct device_node *of_root;
EXPORT_SYMBOL(of_root);

struct device_node *of_chosen;
struct device_node *of_aliases;
struct device_node *of_stdout;
static const char *of_stdout_options;

/* use when traversing tree through the child, sibling,
 * or parent members of struct device_node.
 */
DEFINE_RAW_SPINLOCK(devtree_lock);

static struct device_node *
__of_get_next_child(const struct device_node *node,
                    struct device_node *prev)
{
    struct device_node *next;

    if (!node)
        return NULL;

    next = prev ? prev->sibling : node->child;
    for (; next; next = next->sibling)
        if (of_node_get(next))
            break;
    of_node_put(prev);
    return next;
}
#define __for_each_child_of_node(parent, child) \
    for (child = __of_get_next_child(parent, NULL); child != NULL; \
         child = __of_get_next_child(parent, child))

static struct property *
__of_find_property(const struct device_node *np,
                   const char *name, int *lenp)
{
    struct property *pp;

    if (!np)
        return NULL;

    for (pp = np->properties; pp; pp = pp->next) {
        if (of_prop_cmp(pp->name, name) == 0) {
            if (lenp)
                *lenp = pp->length;
            break;
        }
    }

    return pp;
}

struct property *
of_find_property(const struct device_node *np,
                 const char *name, int *lenp)
{
    struct property *pp;
    unsigned long flags;

    raw_spin_lock_irqsave(&devtree_lock, flags);
    pp = __of_find_property(np, name, lenp);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);

    return pp;
}
EXPORT_SYMBOL(of_find_property);

/*
 * Find a property with a given name for a given node
 * and return the value.
 */
const void *
of_get_property(const struct device_node *np, const char *name, int *lenp)
{
    struct property *pp = of_find_property(np, name, lenp);
    return pp ? pp->value : NULL;
}
EXPORT_SYMBOL(of_get_property);

/**
 * of_alias_scan - Scan all properties of the 'aliases' node
 *
 * The function scans all the properties of the 'aliases' node and populates
 * the global lookup table with the properties.  It returns the
 * number of alias properties found, or an error code in case of failure.
 *
 * @dt_alloc:   An allocator that provides a virtual address to memory
 *      for storing the resulting tree
 */
void of_alias_scan(void * (*dt_alloc)(u64 size, u64 align))
{
    //struct property *pp;

    of_aliases = of_find_node_by_path("/aliases");
    of_chosen = of_find_node_by_path("/chosen");
    if (of_chosen == NULL)
        of_chosen = of_find_node_by_path("/chosen@0");

    if (of_chosen) {
        /* linux,stdout-path and /aliases/stdout are for legacy compatibility */
        const char *name = NULL;

        if (of_property_read_string(of_chosen, "stdout-path", &name))
            of_property_read_string(of_chosen, "linux,stdout-path",
                                    &name);

        if (name)
            of_stdout = of_find_node_opts_by_path(name, &of_stdout_options);
    }

    if (!of_aliases)
        return;

    panic("%s: END!\n", __func__);
}

struct device_node *
__of_find_node_by_path(struct device_node *parent, const char *path)
{
    int len;
    struct device_node *child;

    len = strcspn(path, "/:");
    if (!len)
        return NULL;

    __for_each_child_of_node(parent, child) {
        const char *name = kbasename(child->full_name);
        if (strncmp(path, name, len) == 0 && (strlen(name) == len))
            return child;
    }
    return NULL;
}

struct device_node *
__of_find_node_by_full_path(struct device_node *node, const char *path)
{
    const char *separator = strchr(path, ':');

    while (node && *path == '/') {
        struct device_node *tmp = node;

        path++; /* Increment past '/' delimiter */
        node = __of_find_node_by_path(node, path);
        of_node_put(tmp);
        path = strchrnul(path, '/');
        if (separator && separator < path)
            break;
    }
    return node;
}

struct device_node *
of_find_node_opts_by_path(const char *path, const char **opts)
{
    //struct property *pp;
    unsigned long flags;
    struct device_node *np = NULL;
    const char *separator = strchr(path, ':');

    if (opts)
        *opts = separator ? separator + 1 : NULL;

    if (strcmp(path, "/") == 0)
        return of_node_get(of_root);

    /* The path could begin with an alias */
    if (*path != '/') {
        panic("%s: path(%s) begin with an alias!\n", __func__, path);
    }

    /* Step down the tree matching path components */
    raw_spin_lock_irqsave(&devtree_lock, flags);
    if (!np)
        np = of_node_get(of_root);
    np = __of_find_node_by_full_path(np, path);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);
    return np;
}
EXPORT_SYMBOL(of_find_node_opts_by_path);

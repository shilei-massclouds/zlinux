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
#include <linux/hash.h>
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

#define OF_PHANDLE_CACHE_BITS   7
#define OF_PHANDLE_CACHE_SZ BIT(OF_PHANDLE_CACHE_BITS)

static struct device_node *phandle_cache[OF_PHANDLE_CACHE_SZ];

static u32 of_phandle_cache_hash(phandle handle)
{
    return hash_32(handle, OF_PHANDLE_CACHE_BITS);
}

/**
 *  __of_device_is_fail - check if a device has status "fail" or "fail-..."
 *
 *  @device: Node to check status for, with locks already held
 *
 *  Return: True if the status property is set to "fail" or "fail-..." (for any
 *  error code suffix), false otherwise
 */
static bool __of_device_is_fail(const struct device_node *device)
{
    const char *status;

    if (!device)
        return false;

    status = __of_get_property(device, "status", NULL);
    if (status == NULL)
        return false;

    return !strcmp(status, "fail") || !strncmp(status, "fail-", 5);
}

static bool __of_node_is_type(const struct device_node *np, const char *type)
{
    const char *match = __of_get_property(np, "device_type", NULL);

    return np && match && type && !strcmp(match, type);
}

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

/**
 * of_get_next_cpu_node - Iterate on cpu nodes
 * @prev:   previous child of the /cpus node, or NULL to get first
 *
 * Unusable CPUs (those with the status property set to "fail" or "fail-...")
 * will be skipped.
 *
 * Return: A cpu node pointer with refcount incremented, use of_node_put()
 * on it when done. Returns NULL when prev is the last child. Decrements
 * the refcount of prev.
 */
struct device_node *of_get_next_cpu_node(struct device_node *prev)
{
    struct device_node *next = NULL;
    unsigned long flags;
    struct device_node *node;

    if (!prev)
        node = of_find_node_by_path("/cpus");

    raw_spin_lock_irqsave(&devtree_lock, flags);
    if (prev)
        next = prev->sibling;
    else if (node) {
        next = node->child;
        of_node_put(node);
    }
    for (; next; next = next->sibling) {
        if (__of_device_is_fail(next))
            continue;
        if (!(of_node_name_eq(next, "cpu") || __of_node_is_type(next, "cpu")))
            continue;
        if (of_node_get(next))
            break;
    }
    of_node_put(prev);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);
    return next;
}
EXPORT_SYMBOL(of_get_next_cpu_node);

/*
 * Find a property with a given name for a given node
 * and return the value.
 */
const void *__of_get_property(const struct device_node *np,
                              const char *name, int *lenp)
{
    struct property *pp = __of_find_property(np, name, lenp);

    return pp ? pp->value : NULL;
}

bool of_node_name_eq(const struct device_node *np, const char *name)
{
    const char *node_name;
    size_t len;

    if (!np)
        return false;

    node_name = kbasename(np->full_name);
    len = strchrnul(node_name, '@') - node_name;

    return (strlen(name) == len) && (strncmp(node_name, name, len) == 0);
}
EXPORT_SYMBOL(of_node_name_eq);

/**
 * of_get_cpu_hwid - Get the hardware ID from a CPU device node
 *
 * @cpun: CPU number(logical index) for which device node is required
 * @thread: The local thread number to get the hardware ID for.
 *
 * Return: The hardware ID for the CPU node or ~0ULL if not found.
 */
u64 of_get_cpu_hwid(struct device_node *cpun, unsigned int thread)
{
    const __be32 *cell;
    int ac, len;

    ac = of_n_addr_cells(cpun);
    cell = of_get_property(cpun, "reg", &len);
    if (!cell || !ac || ((sizeof(*cell) * ac * (thread + 1)) > len))
        return ~0ULL;

    cell += ac * thread;
    return of_read_number(cell, ac);
}

/**
 * __of_device_is_compatible() - Check if the node matches given constraints
 * @device: pointer to node
 * @compat: required compatible string, NULL or "" for any match
 * @type: required device_type value, NULL or "" for any match
 * @name: required node name, NULL or "" for any match
 *
 * Checks if the given @compat, @type and @name strings match the
 * properties of the given @device. A constraints can be skipped by
 * passing NULL or an empty string as the constraint.
 *
 * Returns 0 for no match, and a positive integer on match. The return
 * value is a relative score with larger values indicating better
 * matches. The score is weighted for the most specific compatible value
 * to get the highest score. Matching type is next, followed by matching
 * name. Practically speaking, this results in the following priority
 * order for matches:
 *
 * 1. specific compatible && type && name
 * 2. specific compatible && type
 * 3. specific compatible && name
 * 4. specific compatible
 * 5. general compatible && type && name
 * 6. general compatible && type
 * 7. general compatible && name
 * 8. general compatible
 * 9. type && name
 * 10. type
 * 11. name
 */
static int
__of_device_is_compatible(const struct device_node *device,
                          const char *compat,
                          const char *type,
                          const char *name)
{
    struct property *prop;
    const char *cp;
    int index = 0, score = 0;

    /* Compatible match has highest priority */
    if (compat && compat[0]) {
        prop = __of_find_property(device, "compatible", NULL);
        for (cp = of_prop_next_string(prop, NULL); cp;
             cp = of_prop_next_string(prop, cp), index++) {
            if (of_compat_cmp(cp, compat, strlen(compat)) == 0) {
                score = INT_MAX/2 - (index << 2);
                break;
            }
        }
        if (!score)
            return 0;
    }

    /* Matching type is better than matching name */
    if (type && type[0]) {
        if (!__of_node_is_type(device, type))
            return 0;
        score += 2;
    }

    /* Matching name is a bit better than not */
    if (name && name[0]) {
        if (!of_node_name_eq(device, name))
            return 0;
        score++;
    }

    return score;
}

/** Checks if the given "compat" string matches one of the strings in
 * the device's "compatible" property
 */
int of_device_is_compatible(const struct device_node *device,
        const char *compat)
{
    unsigned long flags;
    int res;

    raw_spin_lock_irqsave(&devtree_lock, flags);
    res = __of_device_is_compatible(device, compat, NULL, NULL);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);
    return res;
}
EXPORT_SYMBOL(of_device_is_compatible);

int of_bus_n_addr_cells(struct device_node *np)
{
    u32 cells;

    for (; np; np = np->parent)
        if (!of_property_read_u32(np, "#address-cells", &cells))
            return cells;

    /* No #address-cells property for the root node */
    return OF_ROOT_NODE_ADDR_CELLS_DEFAULT;
}

int of_n_addr_cells(struct device_node *np)
{
    if (np->parent)
        np = np->parent;

    return of_bus_n_addr_cells(np);
}
EXPORT_SYMBOL(of_n_addr_cells);

int of_bus_n_size_cells(struct device_node *np)
{
    u32 cells;

    for (; np; np = np->parent)
        if (!of_property_read_u32(np, "#size-cells", &cells))
            return cells;

    /* No #size-cells property for the root node */
    return OF_ROOT_NODE_SIZE_CELLS_DEFAULT;
}

int of_n_size_cells(struct device_node *np)
{
    if (np->parent)
        np = np->parent;

    return of_bus_n_size_cells(np);
}
EXPORT_SYMBOL(of_n_size_cells);

/**
 *  __of_device_is_available - check if a device is available for use
 *
 *  @device: Node to check for availability, with locks already held
 *
 *  Return: True if the status property is absent or set to "okay" or "ok",
 *  false otherwise
 */
static bool __of_device_is_available(const struct device_node *device)
{
    const char *status;
    int statlen;

    if (!device)
        return false;

    status = __of_get_property(device, "status", &statlen);
    if (status == NULL)
        return true;

    if (statlen > 0) {
        if (!strcmp(status, "okay") || !strcmp(status, "ok"))
            return true;
    }

    return false;
}

/**
 *  of_device_is_available - check if a device is available for use
 *
 *  @device: Node to check for availability
 *
 *  Return: True if the status property is absent or set to "okay" or "ok",
 *  false otherwise
 */
bool of_device_is_available(const struct device_node *device)
{
    unsigned long flags;
    bool res;

    raw_spin_lock_irqsave(&devtree_lock, flags);
    res = __of_device_is_available(device);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);
    return res;
}
EXPORT_SYMBOL(of_device_is_available);

/**
 * of_get_next_child - Iterate a node childs
 * @node:   parent node
 * @prev:   previous child of the parent node, or NULL to get first
 *
 * Return: A node pointer with refcount incremented, use of_node_put() on
 * it when done. Returns NULL when prev is the last child. Decrements the
 * refcount of prev.
 */
struct device_node *
of_get_next_child(const struct device_node *node, struct device_node *prev)
{
    struct device_node *next;
    unsigned long flags;

    raw_spin_lock_irqsave(&devtree_lock, flags);
    next = __of_get_next_child(node, prev);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);
    return next;
}
EXPORT_SYMBOL(of_get_next_child);

static const struct of_device_id *
__of_match_node(const struct of_device_id *matches,
                const struct device_node *node)
{
    const struct of_device_id *best_match = NULL;
    int score, best_score = 0;

    if (!matches)
        return NULL;

    for (; matches->name[0] || matches->type[0] || matches->compatible[0]; matches++) {
        score = __of_device_is_compatible(node, matches->compatible,
                                          matches->type, matches->name);
        if (score > best_score) {
            best_match = matches;
            best_score = score;
        }
    }

    return best_match;
}

/**
 * of_match_node - Tell if a device_node has a matching of_match structure
 * @matches:    array of of device match structures to search in
 * @node:   the of device structure to match against
 *
 * Low level utility function used by device matching.
 */
const struct of_device_id *
of_match_node(const struct of_device_id *matches,
              const struct device_node *node)
{
    const struct of_device_id *match;
    unsigned long flags;

    raw_spin_lock_irqsave(&devtree_lock, flags);
    match = __of_match_node(matches, node);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);
    return match;
}
EXPORT_SYMBOL(of_match_node);

/**
 * of_get_parent - Get a node's parent if any
 * @node:   Node to get parent
 *
 * Return: A node pointer with refcount incremented, use
 * of_node_put() on it when done.
 */
struct device_node *of_get_parent(const struct device_node *node)
{
    struct device_node *np;
    unsigned long flags;

    if (!node)
        return NULL;

    raw_spin_lock_irqsave(&devtree_lock, flags);
    np = of_node_get(node->parent);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);
    return np;
}
EXPORT_SYMBOL(of_get_parent);

int __of_parse_phandle_with_args(const struct device_node *np,
                                 const char *list_name,
                                 const char *cells_name,
                                 int cell_count, int index,
                                 struct of_phandle_args *out_args)
{
    struct of_phandle_iterator it;
    int rc, cur_index = 0;

    if (index < 0)
        return -EINVAL;

    /* Loop over the phandles until all the requested entry is found */
    of_for_each_phandle(&it, rc, np, list_name, cells_name, cell_count) {
        /*
         * All of the error cases bail out of the loop, so at
         * this point, the parsing is successful. If the requested
         * index matches, then fill the out_args structure and return,
         * or return -ENOENT for an empty entry.
         */
        rc = -ENOENT;
        if (cur_index == index) {
            if (!it.phandle)
                goto err;

            if (out_args) {
                int c;

                c = of_phandle_iterator_args(&it,
                                             out_args->args, MAX_PHANDLE_ARGS);
                out_args->np = it.node;
                out_args->args_count = c;
            } else {
                of_node_put(it.node);
            }

            /* Found it! return success */
            return 0;
        }

        cur_index++;
    }

    /*
     * Unlock node before returning result; will be one of:
     * -ENOENT : index is for empty phandle
     * -EINVAL : parsing error on data
     */

 err:
    of_node_put(it.node);
    return rc;
}
EXPORT_SYMBOL(__of_parse_phandle_with_args);

int of_phandle_iterator_init(struct of_phandle_iterator *it,
                             const struct device_node *np,
                             const char *list_name,
                             const char *cells_name,
                             int cell_count)
{
    const __be32 *list;
    int size;

    memset(it, 0, sizeof(*it));

    /*
     * one of cell_count or cells_name must be provided to determine the
     * argument length.
     */
    if (cell_count < 0 && !cells_name)
        return -EINVAL;

    list = of_get_property(np, list_name, &size);
    if (!list)
        return -ENOENT;

    it->cells_name = cells_name;
    it->cell_count = cell_count;
    it->parent = np;
    it->list_end = list + size / sizeof(*list);
    it->phandle_end = list;
    it->cur = list;

    return 0;
}
EXPORT_SYMBOL_GPL(of_phandle_iterator_init);

/**
 * of_find_node_by_phandle - Find a node given a phandle
 * @handle: phandle of the node to find
 *
 * Return: A node pointer with refcount incremented, use
 * of_node_put() on it when done.
 */
struct device_node *of_find_node_by_phandle(phandle handle)
{
    struct device_node *np = NULL;
    unsigned long flags;
    u32 handle_hash;

    if (!handle)
        return NULL;

    handle_hash = of_phandle_cache_hash(handle);

    raw_spin_lock_irqsave(&devtree_lock, flags);

    if (phandle_cache[handle_hash] &&
        handle == phandle_cache[handle_hash]->phandle)
        np = phandle_cache[handle_hash];

    if (!np) {
        for_each_of_allnodes(np) {
            if (np->phandle == handle && !of_node_check_flag(np, OF_DETACHED)) {
                phandle_cache[handle_hash] = np;
                break;
            }
        }
    }

    of_node_get(np);
    raw_spin_unlock_irqrestore(&devtree_lock, flags);
    return np;
}
EXPORT_SYMBOL(of_find_node_by_phandle);

int of_phandle_iterator_next(struct of_phandle_iterator *it)
{
    uint32_t count = 0;

    if (it->node) {
        of_node_put(it->node);
        it->node = NULL;
    }

    if (!it->cur || it->phandle_end >= it->list_end)
        return -ENOENT;

    it->cur = it->phandle_end;

    /* If phandle is 0, then it is an empty entry with no arguments. */
    it->phandle = be32_to_cpup(it->cur++);

    if (it->phandle) {

        /*
         * Find the provider node and parse the #*-cells property to
         * determine the argument length.
         */
        it->node = of_find_node_by_phandle(it->phandle);

        if (it->cells_name) {
            if (!it->node) {
                pr_err("%pOF: could not find phandle %d\n",
                       it->parent, it->phandle);
                goto err;
            }

            if (of_property_read_u32(it->node, it->cells_name, &count)) {
                /*
                 * If both cell_count and cells_name is given,
                 * fall back to cell_count in absence
                 * of the cells_name property
                 */
                if (it->cell_count >= 0) {
                    count = it->cell_count;
                } else {
                    pr_err("%pOF: could not get %s for %pOF\n",
                           it->parent,
                           it->cells_name,
                           it->node);
                    goto err;
                }
            }
        } else {
            count = it->cell_count;
        }

        /*
         * Make sure that the arguments actually fit in the remaining
         * property data length
         */
        if (it->cur + count > it->list_end) {
            if (it->cells_name)
                pr_err("%pOF: %s = %d found %td\n",
                       it->parent, it->cells_name,
                       count, it->list_end - it->cur);
            else
                pr_err("%pOF: phandle %s needs %d, found %td\n",
                       it->parent, of_node_full_name(it->node),
                       count, it->list_end - it->cur);
            goto err;
        }
    }

    it->phandle_end = it->cur + count;
    it->cur_count = count;

    return 0;

err:
    if (it->node) {
        of_node_put(it->node);
        it->node = NULL;
    }

    return -EINVAL;
}
EXPORT_SYMBOL_GPL(of_phandle_iterator_next);

int of_phandle_iterator_args(struct of_phandle_iterator *it,
                             uint32_t *args,
                             int size)
{
    int i, count;

    count = it->cur_count;

    if (WARN_ON(size < count))
        count = size;

    for (i = 0; i < count; i++)
        args[i] = be32_to_cpup(it->cur++);

    return count;
}

struct device_node *__of_find_all_nodes(struct device_node *prev)
{
    struct device_node *np;
    if (!prev) {
        np = of_root;
    } else if (prev->child) {
        np = prev->child;
    } else {
        /* Walk back up looking for a sibling, or the end of the structure */
        np = prev;
        while (np->parent && !np->sibling)
            np = np->parent;
        np = np->sibling; /* Might be null at the end of the tree */
    }
    return np;
}

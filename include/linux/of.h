/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _LINUX_OF_H
#define _LINUX_OF_H
/*
 * Definitions for talking to the Open Firmware PROM on
 * Power Macintosh and other computers.
 *
 * Copyright (C) 1996-2005 Paul Mackerras.
 *
 * Updates for PPC64 by Peter Bergner & David Engebretsen, IBM Corp.
 * Updates for SPARC64 by David S. Miller
 * Derived from PowerPC and Sparc prom.h files by Stephen Rothwell, IBM Corp.
 */
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/kobject.h>
#include <linux/mod_devicetable.h>
#include <linux/spinlock.h>
/*
#include <linux/topology.h>
#include <linux/notifier.h>
*/
#include <linux/property.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/numa.h>

#include <asm/byteorder.h>
#include <asm/errno.h>

/*
 * struct device_node flag descriptions
 * (need to be visible even when !CONFIG_OF)
 */
#define OF_DYNAMIC          1 /* (and properties) allocated via kmalloc */
#define OF_DETACHED         2 /* detached from the device tree */
#define OF_POPULATED        3 /* device already created */
#define OF_POPULATED_BUS    4 /* platform bus created for children */
#define OF_OVERLAY          5 /* allocated for an overlay */
#define OF_OVERLAY_FREE_CSET    6 /* in overlay cset being freed */

#define OF_BAD_ADDR ((u64)-1)

#define of_prop_cmp(s1, s2)     strcmp((s1), (s2))

#if defined(CONFIG_OF) && !defined(MODULE)
#define _OF_DECLARE(table, name, compat, fn, fn_type)   \
    static const struct of_device_id __of_table_##name  \
        __used __section("__" #table "_of_table")       \
        __aligned(__alignof__(struct of_device_id))     \
         = { .compatible = compat,                      \
             .data = (fn == (fn_type)NULL) ? fn : fn  }
#else
# error "MODULE is NOT supported!\n"
#endif

typedef int (*of_init_fn_2)(struct device_node *, struct device_node *);
typedef int (*of_init_fn_1_ret)(struct device_node *);
typedef void (*of_init_fn_1)(struct device_node *);

#define OF_DECLARE_1(table, name, compat, fn) \
    _OF_DECLARE(table, name, compat, fn, of_init_fn_1)
#define OF_DECLARE_1_RET(table, name, compat, fn) \
    _OF_DECLARE(table, name, compat, fn, of_init_fn_1_ret)
#define OF_DECLARE_2(table, name, compat, fn) \
    _OF_DECLARE(table, name, compat, fn, of_init_fn_2)

typedef u32 phandle;
typedef u32 ihandle;

struct property {
    char    *name;
    int     length;
    void    *value;
    struct property *next;
    struct bin_attribute attr;
};

struct device_node {
    const char *name;
    phandle phandle;
    const char *full_name;
    struct fwnode_handle fwnode;

    struct  property *properties;
    struct  property *deadprops;    /* removed properties */
    struct  device_node *parent;
    struct  device_node *child;
    struct  device_node *sibling;
    struct  kobject kobj;
    unsigned long _flags;
    void    *data;
};

#define MAX_PHANDLE_ARGS 16
struct of_phandle_args {
    struct device_node *np;
    int args_count;
    uint32_t args[MAX_PHANDLE_ARGS];
};

struct of_phandle_iterator {
    /* Common iterator information */
    const char *cells_name;
    int cell_count;
    const struct device_node *parent;

    /* List size information */
    const __be32 *list_end;
    const __be32 *phandle_end;

    /* Current position state */
    const __be32 *cur;
    uint32_t cur_count;
    phandle phandle;
    struct device_node *node;
};

/* Pointer for first entry in chain of all nodes. */
extern struct device_node *of_root;
extern struct device_node *of_chosen;
extern struct device_node *of_aliases;
extern struct device_node *of_stdout;

/* initialize a node */
extern struct kobj_type of_node_ktype;

extern const void *
of_get_property(const struct device_node *node,
                const char *name, int *lenp);

extern void of_alias_scan(void * (*dt_alloc)(u64 size, u64 align));

extern struct property *of_find_property(const struct device_node *np,
                     const char *name,
                     int *lenp);
extern int of_property_count_elems_of_size(const struct device_node *np,
                const char *propname, int elem_size);
extern int of_property_read_u32_index(const struct device_node *np,
                       const char *propname,
                       u32 index, u32 *out_value);
extern int of_property_read_u64_index(const struct device_node *np,
                       const char *propname,
                       u32 index, u64 *out_value);
extern int of_property_read_variable_u8_array(const struct device_node *np,
                    const char *propname, u8 *out_values,
                    size_t sz_min, size_t sz_max);
extern int of_property_read_variable_u16_array(const struct device_node *np,
                    const char *propname, u16 *out_values,
                    size_t sz_min, size_t sz_max);
extern int of_property_read_variable_u32_array(const struct device_node *np,
                    const char *propname,
                    u32 *out_values,
                    size_t sz_min,
                    size_t sz_max);
extern int of_property_read_u64(const struct device_node *np,
                const char *propname, u64 *out_value);
extern int of_property_read_variable_u64_array(const struct device_node *np,
                    const char *propname,
                    u64 *out_values,
                    size_t sz_min,
                    size_t sz_max);

/* initialize a node */
extern struct kobj_type of_node_ktype;
extern const struct fwnode_operations of_fwnode_ops;
static inline void of_node_init(struct device_node *node)
{
    kobject_init(&node->kobj, &of_node_ktype);
    fwnode_init(&node->fwnode, &of_fwnode_ops);
}

/*
 * OF address retrieval & translation
 */

/* Helper to read a big number; size is in cells (not bytes) */
static inline u64 of_read_number(const __be32 *cell, int size)
{
    u64 r = 0;
    for (; size--; cell++)
        r = (r << 32) | be32_to_cpu(*cell);
    return r;
}

static inline void of_node_set_flag(struct device_node *n, unsigned long flag)
{
    set_bit(flag, &n->_flags);
}

extern struct device_node *
of_find_node_opts_by_path(const char *path, const char **opts);

static inline struct device_node *of_find_node_by_path(const char *path)
{
    return of_find_node_opts_by_path(path, NULL);
}

/* Dummy ref counting routines - to be implemented later */
static inline struct device_node *of_node_get(struct device_node *node)
{
    return node;
}

static inline void of_node_put(struct device_node *node) { }

extern int of_property_read_string(const struct device_node *np,
                                   const char *propname,
                                   const char **out_string);

#define for_each_of_cpu_node(cpu) \
    for (cpu = of_get_next_cpu_node(NULL); cpu != NULL; \
         cpu = of_get_next_cpu_node(cpu))

extern struct device_node *of_get_next_cpu_node(struct device_node *prev);

extern bool of_node_name_eq(const struct device_node *np, const char *name);

extern u64 of_get_cpu_hwid(struct device_node *cpun, unsigned int thread);

extern int of_device_is_compatible(const struct device_node *device,
                                   const char *);

extern bool of_device_is_available(const struct device_node *device);

const char *of_prop_next_string(struct property *prop, const char *cur);

extern int of_n_addr_cells(struct device_node *np);
extern int of_n_size_cells(struct device_node *np);

/**
 * of_property_read_u32_array - Find and read an array of 32 bit integers
 * from a property.
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_values: pointer to return value, modified only if return value is 0.
 * @sz:     number of array elements to read
 *
 * Search for a property in a device node and read 32-bit value(s) from
 * it.
 *
 * Return: 0 on success, -EINVAL if the property does not exist,
 * -ENODATA if property does not have a value, and -EOVERFLOW if the
 * property data isn't large enough.
 *
 * The out_values is modified only if a valid u32 value can be decoded.
 */
static inline int of_property_read_u32_array(const struct device_node *np,
                                             const char *propname,
                                             u32 *out_values, size_t sz)
{
    int ret = of_property_read_variable_u32_array(np, propname,
                                                  out_values, sz, 0);
    if (ret >= 0)
        return 0;
    else
        return ret;
}

static inline int of_property_read_u32(const struct device_node *np,
                                       const char *propname, u32 *out_value)
{
    return of_property_read_u32_array(np, propname, out_value, 1);
}

/* Default string compare functions, Allow arch asm/prom.h to override */
#if !defined(of_compat_cmp)
#define of_compat_cmp(s1, s2, l)    strcasecmp((s1), (s2))
#define of_prop_cmp(s1, s2)         strcmp((s1), (s2))
#define of_node_cmp(s1, s2)         strcasecmp((s1), (s2))
#endif

static inline int of_node_to_nid(struct device_node *device)
{
    return NUMA_NO_NODE;
}

static inline bool of_have_populated_dt(void)
{
    return of_root != NULL;
}

extern struct device_node *
of_get_next_child(const struct device_node *node, struct device_node *prev);

extern const struct of_device_id *
of_match_node(const struct of_device_id *matches,
              const struct device_node *node);

static inline int
of_node_check_flag(const struct device_node *n, unsigned long flag)
{
    return test_bit(flag, &n->_flags);
}

static inline int
of_node_test_and_set_flag(struct device_node *n, unsigned long flag)
{
    return test_and_set_bit(flag, &n->_flags);
}

static inline void of_node_clear_flag(struct device_node *n, unsigned long flag)
{
    clear_bit(flag, &n->_flags);
}

extern struct device_node *of_get_parent(const struct device_node *node);

#define for_each_child_of_node(parent, child) \
    for (child = of_get_next_child(parent, NULL); child != NULL; \
         child = of_get_next_child(parent, child))

extern int
of_property_read_string_helper(const struct device_node *np,
                               const char *propname,
                               const char **out_strs, size_t sz, int index);

/**
 * of_property_read_string_index() - Find and read a string from a multiple
 * strings property.
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @index:  index of the string in the list of strings
 * @output: pointer to null terminated return string, modified only if
 *      return value is 0.
 *
 * Search for a property in a device tree node and retrieve a null
 * terminated string value (pointer to data, not a copy) in the list of strings
 * contained in that property.
 *
 * Return: 0 on success, -EINVAL if the property does not exist, -ENODATA if
 * property does not have a value, and -EILSEQ if the string is not
 * null-terminated within the length of the property data.
 *
 * The out_string pointer is modified only if a valid string can be decoded.
 */
static inline int
of_property_read_string_index(const struct device_node *np,
                              const char *propname,
                              int index, const char **output)
{
    int rc = of_property_read_string_helper(np, propname, output, 1, index);
    return rc < 0 ? rc : 0;
}

static inline bool is_of_node(const struct fwnode_handle *fwnode)
{
    return !IS_ERR_OR_NULL(fwnode) && fwnode->ops == &of_fwnode_ops;
}

#define to_of_node(__fwnode)    \
({                              \
    typeof(__fwnode) __to_of_node_fwnode = (__fwnode);  \
                                                        \
    is_of_node(__to_of_node_fwnode) ? \
    container_of(__to_of_node_fwnode, struct device_node, fwnode) : NULL; \
})

#define of_fwnode_handle(node)                      \
({                                                  \
    typeof(node) __of_fwnode_handle_node = (node);  \
                                                    \
    __of_fwnode_handle_node ? &__of_fwnode_handle_node->fwnode : NULL; \
})

#define of_property_for_each_string(np, propname, prop, s)  \
    for (prop = of_find_property(np, propname, NULL),   \
        s = of_prop_next_string(prop, NULL);        \
        s;                      \
        s = of_prop_next_string(prop, s))

extern int __of_parse_phandle_with_args(const struct device_node *np,
    const char *list_name, const char *cells_name, int cell_count,
    int index, struct of_phandle_args *out_args);

/**
 * of_parse_phandle_with_args() - Find a node pointed by phandle in a list
 * @np:     pointer to a device tree node containing a list
 * @list_name:  property name that contains a list
 * @cells_name: property name that specifies phandles' arguments count
 * @index:  index of a phandle to parse out
 * @out_args:   optional pointer to output arguments structure (will be filled)
 *
 * This function is useful to parse lists of phandles and their arguments.
 * Returns 0 on success and fills out_args, on error returns appropriate
 * errno value.
 *
 * Caller is responsible to call of_node_put() on the returned out_args->np
 * pointer.
 *
 * Example::
 *
 *  phandle1: node1 {
 *  #list-cells = <2>;
 *  };
 *
 *  phandle2: node2 {
 *  #list-cells = <1>;
 *  };
 *
 *  node3 {
 *  list = <&phandle1 1 2 &phandle2 3>;
 *  };
 *
 * To get a device_node of the ``node2`` node you may call this:
 * of_parse_phandle_with_args(node3, "list", "#list-cells", 1, &args);
 */
static inline int
of_parse_phandle_with_args(const struct device_node *np,
                           const char *list_name,
                           const char *cells_name,
                           int index,
                           struct of_phandle_args *out_args)
{
    int cell_count = -1;

    /* If cells_name is NULL we assume a cell count of 0 */
    if (!cells_name)
        cell_count = 0;

    return __of_parse_phandle_with_args(np, list_name, cells_name,
                                        cell_count, index, out_args);
}

/* phandle iterator functions */
extern int of_phandle_iterator_init(struct of_phandle_iterator *it,
                                    const struct device_node *np,
                                    const char *list_name,
                                    const char *cells_name,
                                    int cell_count);

extern int of_phandle_iterator_next(struct of_phandle_iterator *it);

extern int of_phandle_iterator_args(struct of_phandle_iterator *it,
                                    uint32_t *args,
                                    int size);

#define of_for_each_phandle(it, err, np, ln, cn, cc)                \
    for (of_phandle_iterator_init((it), (np), (ln), (cn), (cc)),    \
         err = of_phandle_iterator_next(it);                        \
         err == 0;                                                  \
         err = of_phandle_iterator_next(it))

extern struct device_node *__of_find_all_nodes(struct device_node *prev);

#define for_each_of_allnodes_from(from, dn) \
    for (dn = __of_find_all_nodes(from); dn; dn = __of_find_all_nodes(dn))

#define for_each_of_allnodes(dn) for_each_of_allnodes_from(NULL, dn)

static inline const char *of_node_full_name(const struct device_node *np)
{
    return np ? np->full_name : "<no-node>";
}

extern struct device_node *of_find_node_by_phandle(phandle handle);

/**
 * of_property_read_bool - Find a property
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 *
 * Search for a property in a device node.
 *
 * Return: true if the property exists false otherwise.
 */
static inline bool of_property_read_bool(const struct device_node *np,
                                         const char *propname)
{
    struct property *prop = of_find_property(np, propname, NULL);

    return prop ? true : false;
}

extern int of_device_compatible_match(struct device_node *device,
                                      const char *const *compat);

extern struct device_node *
of_find_matching_node_and_match(struct device_node *from,
                                const struct of_device_id *matches,
                                const struct of_device_id **match);

#define for_each_matching_node_and_match(dn, matches, match) \
    for (dn = of_find_matching_node_and_match(NULL, matches, match); \
         dn; dn = of_find_matching_node_and_match(dn, matches, match))

extern int
of_property_match_string(const struct device_node *np, const char *propname,
                         const char *string);

#define for_each_available_child_of_node(parent, child) \
    for (child = of_get_next_available_child(parent, NULL); child != NULL; \
         child = of_get_next_available_child(parent, child))

extern struct device_node *
of_get_next_available_child(const struct device_node *node,
                            struct device_node *prev);

static inline int of_get_available_child_count(const struct device_node *np)
{
    struct device_node *child;
    int num = 0;

    for_each_available_child_of_node(np, child)
        num++;

    return num;
}

extern struct device_node *
of_get_compatible_child(const struct device_node *parent,
                        const char *compatible);
extern struct device_node *
of_get_child_by_name(const struct device_node *node, const char *name);

extern bool of_device_is_big_endian(const struct device_node *device);

extern int of_alias_get_id(struct device_node *np, const char *stem);

bool of_console_check(struct device_node *dn, char *name, int index);

/**
 * of_property_read_u8_array - Find and read an array of u8 from a property.
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_values: pointer to return value, modified only if return value is 0.
 * @sz:     number of array elements to read
 *
 * Search for a property in a device node and read 8-bit value(s) from
 * it.
 *
 * dts entry of array should be like:
 *  ``property = /bits/ 8 <0x50 0x60 0x70>;``
 *
 * Return: 0 on success, -EINVAL if the property does not exist,
 * -ENODATA if property does not have a value, and -EOVERFLOW if the
 * property data isn't large enough.
 *
 * The out_values is modified only if a valid u8 value can be decoded.
 */
static inline
int of_property_read_u8_array(const struct device_node *np,
                              const char *propname,
                              u8 *out_values, size_t sz)
{
    int ret = of_property_read_variable_u8_array(np, propname,
                                                 out_values,
                                                 sz, 0);
    if (ret >= 0)
        return 0;
    else
        return ret;
}

/**
 * of_property_read_u16_array - Find and read an array of u16 from a property.
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_values: pointer to return value, modified only if return value is 0.
 * @sz:     number of array elements to read
 *
 * Search for a property in a device node and read 16-bit value(s) from
 * it.
 *
 * dts entry of array should be like:
 *  ``property = /bits/ 16 <0x5000 0x6000 0x7000>;``
 *
 * Return: 0 on success, -EINVAL if the property does not exist,
 * -ENODATA if property does not have a value, and -EOVERFLOW if the
 * property data isn't large enough.
 *
 * The out_values is modified only if a valid u16 value can be decoded.
 */
static inline int of_property_read_u16_array(const struct device_node *np,
                         const char *propname,
                         u16 *out_values, size_t sz)
{
    int ret = of_property_read_variable_u16_array(np, propname, out_values,
                              sz, 0);
    if (ret >= 0)
        return 0;
    else
        return ret;
}

/**
 * of_property_read_u64_array - Find and read an array of 64 bit integers
 * from a property.
 *
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_values: pointer to return value, modified only if return value is 0.
 * @sz:     number of array elements to read
 *
 * Search for a property in a device node and read 64-bit value(s) from
 * it.
 *
 * Return: 0 on success, -EINVAL if the property does not exist,
 * -ENODATA if property does not have a value, and -EOVERFLOW if the
 * property data isn't large enough.
 *
 * The out_values is modified only if a valid u64 value can be decoded.
 */
static inline int of_property_read_u64_array(const struct device_node *np,
                         const char *propname,
                         u64 *out_values, size_t sz)
{
    int ret = of_property_read_variable_u64_array(np, propname, out_values,
                              sz, 0);
    if (ret >= 0)
        return 0;
    else
        return ret;
}

/**
 * of_property_read_string_array() - Read an array of strings from a multiple
 * strings property.
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 * @out_strs:   output array of string pointers.
 * @sz:     number of array elements to read.
 *
 * Search for a property in a device tree node and retrieve a list of
 * terminated string values (pointer to data, not a copy) in that property.
 *
 * Return: If @out_strs is NULL, the number of strings in the property is returned.
 */
static inline int of_property_read_string_array(const struct device_node *np,
                        const char *propname, const char **out_strs,
                        size_t sz)
{
    return of_property_read_string_helper(np, propname, out_strs, sz, 0);
}

/**
 * of_property_count_strings() - Find and return the number of strings from a
 * multiple strings property.
 * @np:     device node from which the property value is to be read.
 * @propname:   name of the property to be searched.
 *
 * Search for a property in a device tree node and retrieve the number of null
 * terminated string contain in it.
 *
 * Return: The number of strings on success, -EINVAL if the property does not
 * exist, -ENODATA if property does not have a value, and -EILSEQ if the string
 * is not null-terminated within the length of the property data.
 */
static inline int of_property_count_strings(const struct device_node *np,
                        const char *propname)
{
    return of_property_read_string_helper(np, propname, NULL, 0, 0);
}

/**
 * of_parse_phandle - Resolve a phandle property to a device_node pointer
 * @np: Pointer to device node holding phandle property
 * @phandle_name: Name of property holding a phandle value
 * @index: For properties holding a table of phandles, this is the index into
 *         the table
 *
 * Return: The device_node pointer with refcount incremented.  Use
 * of_node_put() on it when done.
 */
static inline
struct device_node *of_parse_phandle(const struct device_node *np,
                                     const char *phandle_name,
                                     int index)
{
    struct of_phandle_args args;

    if (__of_parse_phandle_with_args(np, phandle_name, NULL, 0,
                     index, &args))
        return NULL;

    return args.np;
}

extern struct device_node *of_get_next_parent(struct device_node *node);

#define for_each_property_of_node(dn, pp) \
    for (pp = dn->properties; pp != NULL; pp = pp->next)

extern int
of_parse_phandle_with_args_map(const struct device_node *np,
                               const char *list_name,
                               const char *stem_name, int index,
                               struct of_phandle_args *out_args);

#endif /* _LINUX_OF_H */

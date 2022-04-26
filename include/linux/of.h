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
/*
#include <linux/kobject.h>
#include <linux/mod_devicetable.h>
*/
#include <linux/spinlock.h>
/*
#include <linux/topology.h>
#include <linux/notifier.h>
#include <linux/property.h>
*/
#include <linux/list.h>
#include <linux/sysfs.h>

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
    //struct fwnode_handle fwnode;

    struct  property *properties;
    struct  property *deadprops;    /* removed properties */
    struct  device_node *parent;
    struct  device_node *child;
    struct  device_node *sibling;
    //struct  kobject kobj;
    unsigned long _flags;
    void    *data;
};

/* Pointer for first entry in chain of all nodes. */
extern struct device_node *of_root;
extern struct device_node *of_chosen;
extern struct device_node *of_aliases;
extern struct device_node *of_stdout;

extern const void *
of_get_property(const struct device_node *node,
                const char *name, int *lenp);

extern struct property *
of_find_property(const struct device_node *np,
                 const char *name, int *lenp);

extern void of_alias_scan(void * (*dt_alloc)(u64 size, u64 align));

static inline void of_node_init(struct device_node *node)
{
#if 0
    kobject_init(&node->kobj, &of_node_ktype);
    node->fwnode.ops = &of_fwnode_ops;
#endif
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

#endif /* _LINUX_OF_H */

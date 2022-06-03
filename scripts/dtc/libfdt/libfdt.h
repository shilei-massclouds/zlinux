/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
#ifndef LIBFDT_H
#define LIBFDT_H
/*
 * libfdt - Flat Device Tree manipulation
 * Copyright (C) 2006 David Gibson, IBM Corporation.
 */

#include "libfdt_env.h"
#include "fdt.h"

#define FDT_FIRST_SUPPORTED_VERSION 0x02
#define FDT_LAST_SUPPORTED_VERSION  0x11

/* Error codes: informative error codes */
#define FDT_ERR_NOTFOUND        1

/* Error codes: codes for bad parameters */
#define FDT_ERR_BADOFFSET       4
#define FDT_ERR_BADPATH         5
#define FDT_ERR_BADSTATE        7

/* Error codes: codes for bad device tree blobs */
#define FDT_ERR_TRUNCATED       8
#define FDT_ERR_BADMAGIC        9
#define FDT_ERR_BADVERSION      10
#define FDT_ERR_BADSTRUCTURE    11
#define FDT_ERR_INTERNAL        13

/**********************************************************************/
/* Low-level functions (you probably don't need these)                */
/**********************************************************************/

uint32_t fdt_next_tag(const void *fdt, int offset, int *nextoffset);

static inline uint32_t fdt32_ld(const fdt32_t *p)
{
    const uint8_t *bp = (const uint8_t *)p;

    return ((uint32_t)bp[0] << 24) | ((uint32_t)bp[1] << 16) |
        ((uint32_t)bp[2] << 8) | bp[3];
}

/**********************************************************************/
/* General functions                                                  */
/**********************************************************************/
#define fdt_get_header(fdt, field) \
    (fdt32_ld(&((const struct fdt_header *)(fdt))->field))
#define fdt_magic(fdt)          (fdt_get_header(fdt, magic))
#define fdt_totalsize(fdt)      (fdt_get_header(fdt, totalsize))
#define fdt_off_dt_struct(fdt)  (fdt_get_header(fdt, off_dt_struct))
#define fdt_off_dt_strings(fdt) (fdt_get_header(fdt, off_dt_strings))
#define fdt_off_mem_rsvmap(fdt) (fdt_get_header(fdt, off_mem_rsvmap))
#define fdt_version(fdt)        (fdt_get_header(fdt, version))
#define fdt_last_comp_version(fdt)  (fdt_get_header(fdt, last_comp_version))
#define fdt_size_dt_strings(fdt)    (fdt_get_header(fdt, size_dt_strings))
#define fdt_size_dt_struct(fdt) (fdt_get_header(fdt, size_dt_struct))

/**
 * fdt_check_header - sanity check a device tree header

 * @fdt: pointer to data which might be a flattened device tree
 *
 * fdt_check_header() checks that the given buffer contains what
 * appears to be a flattened device tree, and that the header contains
 * valid information (to the extent that can be determined from the
 * header alone).
 *
 * returns:
 *     0, if the buffer appears to contain a valid device tree
 *     -FDT_ERR_BADMAGIC,
 *     -FDT_ERR_BADVERSION,
 *     -FDT_ERR_BADSTATE,
 *     -FDT_ERR_TRUNCATED, standard meanings, as above
 */
int fdt_check_header(const void *fdt);

const char *fdt_get_name(const void *fdt, int nodeoffset, int *lenp);

const void *fdt_getprop(const void *fdt, int nodeoffset,
                        const char *name, int *lenp);

int fdt_get_mem_rsv(const void *fdt, int n,
                    uint64_t *address, uint64_t *size);

static inline uint64_t fdt64_ld(const fdt64_t *p)
{
    const uint8_t *bp = (const uint8_t *)p;

    return ((uint64_t)bp[0] << 56)
        | ((uint64_t)bp[1] << 48)
        | ((uint64_t)bp[2] << 40)
        | ((uint64_t)bp[3] << 32)
        | ((uint64_t)bp[4] << 24)
        | ((uint64_t)bp[5] << 16)
        | ((uint64_t)bp[6] << 8)
        | bp[7];
}

/***********************
 * Traversal functions
 ***********************/
int fdt_next_node(const void *fdt, int offset, int *depth);

int fdt_first_property_offset(const void *fdt, int nodeoffset);
int fdt_next_property_offset(const void *fdt, int offset);

const void *fdt_getprop_by_offset(const void *fdt, int offset,
                                  const char **namep, int *lenp);

/**
 * fdt_path_offset - find a tree node by its full path
 * @fdt: pointer to the device tree blob
 * @path: full path of the node to locate
 *
 * fdt_path_offset() finds a node of a given path in the device tree.
 * Each path component may omit the unit address portion, but the
 * results of this are undefined if any such path component is
 * ambiguous (that is if there are multiple nodes at the relevant
 * level matching the given component, differentiated only by unit
 * address).
 *
 * returns:
 *  structure block offset of the node with the requested path (>=0), on
 *      success
 *  -FDT_ERR_BADPATH, given path does not begin with '/' or is invalid
 *  -FDT_ERR_NOTFOUND, if the requested node does not exist
 *      -FDT_ERR_BADMAGIC,
 *  -FDT_ERR_BADVERSION,
 *  -FDT_ERR_BADSTATE,
 *  -FDT_ERR_BADSTRUCTURE,
 *  -FDT_ERR_TRUNCATED, standard meanings.
 */
int fdt_path_offset(const void *fdt, const char *path);

/**
 * fdt_for_each_subnode - iterate over all subnodes of a parent
 *
 * @node:   child node (int, lvalue)
 * @fdt:    FDT blob (const void *)
 * @parent: parent node (int)
 *
 * This is actually a wrapper around a for loop and would be used like so:
 *
 *  fdt_for_each_subnode(node, fdt, parent) {
 *      Use node
 *      ...
 *  }
 *
 *  if ((node < 0) && (node != -FDT_ERR_NOTFOUND)) {
 *      Error handling
 *  }
 *
 * Note that this is implemented as a macro and @node is used as
 * iterator in the loop. The parent variable be constant or even a
 * literal.
 */
#define fdt_for_each_subnode(node, fdt, parent)     \
    for (node = fdt_first_subnode(fdt, parent); \
         node >= 0;                 \
         node = fdt_next_subnode(fdt, node))
/**
 * fdt_for_each_subnode - iterate over all subnodes of a parent
 *
 * @node:   child node (int, lvalue)
 * @fdt:    FDT blob (const void *)
 * @parent: parent node (int)
 *
 * This is actually a wrapper around a for loop and would be used like so:
 *
 *  fdt_for_each_subnode(node, fdt, parent) {
 *      Use node
 *      ...
 *  }
 *
 *  if ((node < 0) && (node != -FDT_ERR_NOTFOUND)) {
 *      Error handling
 *  }
 *
 * Note that this is implemented as a macro and @node is used as
 * iterator in the loop. The parent variable be constant or even a
 * literal.
 */
#define fdt_for_each_subnode(node, fdt, parent) \
    for (node = fdt_first_subnode(fdt, parent); \
         node >= 0;                             \
         node = fdt_next_subnode(fdt, node))

/**
 * fdt_first_subnode() - get offset of first direct subnode
 * @fdt:    FDT blob
 * @offset: Offset of node to check
 *
 * Return: offset of first subnode, or -FDT_ERR_NOTFOUND if there is none
 */
int fdt_first_subnode(const void *fdt, int offset);

/**
 * fdt_next_subnode() - get offset of next direct subnode
 * @fdt:    FDT blob
 * @offset: Offset of previous subnode
 *
 * After first calling fdt_first_subnode(), call this function repeatedly to
 * get direct subnodes of a parent node.
 *
 * Return: offset of next subnode, or -FDT_ERR_NOTFOUND if there are no more
 *         subnodes
 */
int fdt_next_subnode(const void *fdt, int offset);

#endif /* LIBFDT_H */

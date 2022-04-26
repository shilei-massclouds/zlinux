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


#endif /* LIBFDT_H */

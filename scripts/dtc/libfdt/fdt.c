// SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause)
/*
 * libfdt - Flat Device Tree manipulation
 * Copyright (C) 2006 David Gibson, IBM Corporation.
 */
#include "libfdt_env.h"

#include <fdt.h>
#include <libfdt.h>

#include "libfdt_internal.h"

/*
 * Minimal sanity check for a read-only tree. fdt_ro_probe_() checks
 * that the given buffer contains what appears to be a flattened
 * device tree with sane information in its header.
 */
int32_t fdt_ro_probe_(const void *fdt)
{
    uint32_t totalsize = fdt_totalsize(fdt);

    if (fdt_magic(fdt) == FDT_MAGIC) {
        /* Complete tree */
        if (fdt_version(fdt) < FDT_FIRST_SUPPORTED_VERSION)
            return -FDT_ERR_BADVERSION;
        if (fdt_last_comp_version(fdt) > FDT_LAST_SUPPORTED_VERSION)
            return -FDT_ERR_BADVERSION;
    } else if (fdt_magic(fdt) == FDT_SW_MAGIC) {
        /* Unfinished sequential-write blob */
        if (fdt_size_dt_struct(fdt) == 0)
            return -FDT_ERR_BADSTATE;
    } else {
        return -FDT_ERR_BADMAGIC;
    }

    if (totalsize < INT32_MAX)
        return totalsize;
    else
        return -FDT_ERR_TRUNCATED;
}

int fdt_check_header(const void *fdt)
{
    if (fdt_magic(fdt) != FDT_MAGIC)
        return -FDT_ERR_BADMAGIC;

    return 0;
}

const void *fdt_offset_ptr(const void *fdt, int offset, unsigned int len)
{
    unsigned absoffset = offset + fdt_off_dt_struct(fdt);

    if ((absoffset < offset)
        || ((absoffset + len) < absoffset)
        || (absoffset + len) > fdt_totalsize(fdt))
        return NULL;

    if (fdt_version(fdt) >= 0x11)
        if (((offset + len) < offset)
            || ((offset + len) > fdt_size_dt_struct(fdt)))
            return NULL;

    return fdt_offset_ptr_(fdt, offset);
}

uint32_t fdt_next_tag(const void *fdt, int startoffset, int *nextoffset)
{
    const fdt32_t *tagp, *lenp;
    uint32_t tag;
    int offset = startoffset;
    const char *p;

    *nextoffset = -FDT_ERR_TRUNCATED;
    tagp = fdt_offset_ptr(fdt, offset, FDT_TAGSIZE);
    if (!tagp)
        return FDT_END; /* premature end */
    tag = fdt32_to_cpu(*tagp);
    offset += FDT_TAGSIZE;

    *nextoffset = -FDT_ERR_BADSTRUCTURE;
    switch (tag) {
    case FDT_BEGIN_NODE:
        /* skip name */
        do {
            p = fdt_offset_ptr(fdt, offset++, 1);
        } while (p && (*p != '\0'));
        if (!p)
            return FDT_END; /* premature end */
        break;

    case FDT_PROP:
        lenp = fdt_offset_ptr(fdt, offset, sizeof(*lenp));
        if (!lenp)
            return FDT_END; /* premature end */
        /* skip-name offset, length and value */
        offset += sizeof(struct fdt_property)
            - FDT_TAGSIZE + fdt32_to_cpu(*lenp);
        if (fdt_version(fdt) < 0x10 && fdt32_to_cpu(*lenp) >= 8 &&
            ((offset - fdt32_to_cpu(*lenp)) % 8) != 0)
            offset += 4;
        break;

    case FDT_END:
    case FDT_END_NODE:
    case FDT_NOP:
        break;

    default:
        return FDT_END;
    }

    if (!fdt_offset_ptr(fdt, startoffset, offset - startoffset))
        return FDT_END; /* premature end */
    *nextoffset = FDT_TAGALIGN(offset);
    return tag;
}

int fdt_check_node_offset_(const void *fdt, int offset)
{
    if ((offset < 0) || (offset % FDT_TAGSIZE) ||
        (fdt_next_tag(fdt, offset, &offset) != FDT_BEGIN_NODE))
        return -FDT_ERR_BADOFFSET;

    return offset;
}

int fdt_check_prop_offset_(const void *fdt, int offset)
{
    if ((offset < 0) || (offset % FDT_TAGSIZE)
        || (fdt_next_tag(fdt, offset, &offset) != FDT_PROP))
        return -FDT_ERR_BADOFFSET;

    return offset;
}

int fdt_next_node(const void *fdt, int offset, int *depth)
{
    int nextoffset = 0;
    uint32_t tag;

    if (offset >= 0)
        if ((nextoffset = fdt_check_node_offset_(fdt, offset)) < 0)
            return nextoffset;

    do {
        offset = nextoffset;
        tag = fdt_next_tag(fdt, offset, &nextoffset);

        switch (tag) {
        case FDT_PROP:
        case FDT_NOP:
            break;

        case FDT_BEGIN_NODE:
            if (depth)
                (*depth)++;
            break;

        case FDT_END_NODE:
            if (depth && ((--(*depth)) < 0))
                return nextoffset;
            break;

        case FDT_END:
            if ((nextoffset >= 0)
                || ((nextoffset == -FDT_ERR_TRUNCATED) && !depth))
                return -FDT_ERR_NOTFOUND;
            else
                return nextoffset;
        }
    } while (tag != FDT_BEGIN_NODE);

    return offset;
}

int fdt_first_subnode(const void *fdt, int offset)
{
    int depth = 0;

    offset = fdt_next_node(fdt, offset, &depth);
    if (offset < 0 || depth != 1)
        return -FDT_ERR_NOTFOUND;

    return offset;
}

int fdt_next_subnode(const void *fdt, int offset)
{
    int depth = 1;

    /*
     * With respect to the parent, the depth of the next subnode will be
     * the same as the last.
     */
    do {
        offset = fdt_next_node(fdt, offset, &depth);
        if (offset < 0 || depth < 1)
            return -FDT_ERR_NOTFOUND;
    } while (depth > 1);

    return offset;
}

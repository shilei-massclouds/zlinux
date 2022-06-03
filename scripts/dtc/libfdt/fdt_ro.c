// SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause)
/*
 * libfdt - Flat Device Tree manipulation
 * Copyright (C) 2006 David Gibson, IBM Corporation.
 */
#include "libfdt_env.h"

#include <fdt.h>
#include <libfdt.h>
#include <linux/printk.h>

#include "libfdt_internal.h"

static int fdt_nodename_eq_(const void *fdt, int offset,
                const char *s, int len)
{
    int olen;
    const char *p = fdt_get_name(fdt, offset, &olen);

    if (!p || olen < len)
        /* short match */
        return 0;

    if (memcmp(p, s, len) != 0)
        return 0;

    if (p[len] == '\0')
        return 1;
    else if (!memchr(s, '@', len) && (p[len] == '@'))
        return 1;
    else
        return 0;
}

const char *fdt_get_name(const void *fdt, int nodeoffset, int *len)
{
    int err;
    const char *nameptr;
    const struct fdt_node_header *nh = fdt_offset_ptr_(fdt, nodeoffset);

    if (((err = fdt_ro_probe_(fdt)) < 0)
        || ((err = fdt_check_node_offset_(fdt, nodeoffset)) < 0))
            goto fail;

    nameptr = nh->name;

    if (fdt_version(fdt) < 0x10) {
        /*
         * For old FDT versions, match the naming conventions of V16:
         * give only the leaf name (after all /). The actual tree
         * contents are loosely checked.
         */
        const char *leaf;
        leaf = strrchr(nameptr, '/');
        if (leaf == NULL) {
            err = -FDT_ERR_BADSTRUCTURE;
            goto fail;
        }
        nameptr = leaf+1;
    }

    if (len)
        *len = strlen(nameptr);

    return nameptr;

 fail:
    if (len)
        *len = err;
    return NULL;
}

static int nextprop_(const void *fdt, int offset)
{
    uint32_t tag;
    int nextoffset;

    do {
        tag = fdt_next_tag(fdt, offset, &nextoffset);

        switch (tag) {
        case FDT_END:
            if (nextoffset >= 0)
                return -FDT_ERR_BADSTRUCTURE;
            else
                return nextoffset;

        case FDT_PROP:
            return offset;
        }
        offset = nextoffset;
    } while (tag == FDT_NOP);

    return -FDT_ERR_NOTFOUND;
}

int fdt_first_property_offset(const void *fdt, int nodeoffset)
{
    int offset;

    if ((offset = fdt_check_node_offset_(fdt, nodeoffset)) < 0)
        return offset;

    return nextprop_(fdt, offset);
}

int fdt_next_property_offset(const void *fdt, int offset)
{
    if ((offset = fdt_check_prop_offset_(fdt, offset)) < 0)
        return offset;

    return nextprop_(fdt, offset);
}

static const struct fdt_property *
fdt_get_property_by_offset_(const void *fdt, int offset, int *lenp)
{
    int err;
    const struct fdt_property *prop;

    if ((err = fdt_check_prop_offset_(fdt, offset)) < 0) {
        if (lenp)
            *lenp = err;
        return NULL;
    }

    prop = fdt_offset_ptr_(fdt, offset);

    if (lenp)
        *lenp = fdt32_ld(&prop->len);

    return prop;
}

const char *
fdt_get_string(const void *fdt, int stroffset, int *lenp)
{
    int32_t totalsize;
    uint32_t absoffset;
    size_t len;
    int err;
    const char *s, *n;

    totalsize = fdt_ro_probe_(fdt);
    err = totalsize;
    if (totalsize < 0)
        goto fail;

    err = -FDT_ERR_BADOFFSET;
    absoffset = stroffset + fdt_off_dt_strings(fdt);
    if (absoffset >= totalsize)
        goto fail;
    len = totalsize - absoffset;

    if (fdt_magic(fdt) == FDT_MAGIC) {
        if (stroffset < 0)
            goto fail;
        if (fdt_version(fdt) >= 17) {
            if (stroffset >= fdt_size_dt_strings(fdt))
                goto fail;
            if ((fdt_size_dt_strings(fdt) - stroffset) < len)
                len = fdt_size_dt_strings(fdt) - stroffset;
        }
    } else if (fdt_magic(fdt) == FDT_SW_MAGIC) {
        if ((stroffset >= 0) || (stroffset < -fdt_size_dt_strings(fdt)))
            goto fail;
        if ((-stroffset) < len)
            len = -stroffset;
    } else {
        err = -FDT_ERR_INTERNAL;
        goto fail;
    }

    s = (const char *)fdt + absoffset;
    n = memchr(s, '\0', len);
    if (!n) {
        /* missing terminating NULL */
        err = -FDT_ERR_TRUNCATED;
        goto fail;
    }

    if (lenp)
        *lenp = n - s;
    return s;

fail:
    if (lenp)
        *lenp = err;
    return NULL;
}

static int fdt_string_eq_(const void *fdt, int stroffset,
                          const char *s, int len)
{
    int slen;
    const char *p = fdt_get_string(fdt, stroffset, &slen);

    return p && (slen == len) && (memcmp(p, s, len) == 0);
}

static const struct fdt_property *
fdt_get_property_namelen_(const void *fdt,
                          int offset,
                          const char *name,
                          int namelen,
                          int *lenp,
                          int *poffset)
{
    for (offset = fdt_first_property_offset(fdt, offset);
         (offset >= 0);
         (offset = fdt_next_property_offset(fdt, offset))) {

        const struct fdt_property *prop;

        prop = fdt_get_property_by_offset_(fdt, offset, lenp);
        if (!prop) {
            offset = -FDT_ERR_INTERNAL;
            break;
        }
        if (fdt_string_eq_(fdt, fdt32_ld(&prop->nameoff), name, namelen)) {
            if (poffset)
                *poffset = offset;
            return prop;
        }
    }

    if (lenp)
        *lenp = offset;
    return NULL;
}

const void *
fdt_getprop_namelen(const void *fdt, int nodeoffset,
                    const char *name, int namelen, int *lenp)
{
    int poffset;
    const struct fdt_property *prop;

    prop = fdt_get_property_namelen_(fdt, nodeoffset, name, namelen,
                                     lenp, &poffset);
    if (!prop)
        return NULL;

    /* Handle realignment */
    if (fdt_version(fdt) < 0x10 &&
        (poffset + sizeof(*prop)) % 8 && fdt32_ld(&prop->len) >= 8)
        return prop->data + 4;
    return prop->data;
}

const void *
fdt_getprop(const void *fdt, int nodeoffset,
            const char *name, int *lenp)
{
    return fdt_getprop_namelen(fdt, nodeoffset, name, strlen(name), lenp);
}

static const struct fdt_reserve_entry *
fdt_mem_rsv(const void *fdt, int n)
{
    int offset = n * sizeof(struct fdt_reserve_entry);
    int absoffset = fdt_off_mem_rsvmap(fdt) + offset;

    if (absoffset < fdt_off_mem_rsvmap(fdt))
        return NULL;
    if (absoffset > fdt_totalsize(fdt) -
        sizeof(struct fdt_reserve_entry))
        return NULL;

    return fdt_mem_rsv_(fdt, n);
}

int fdt_get_mem_rsv(const void *fdt, int n,
                    uint64_t *address, uint64_t *size)
{
    const struct fdt_reserve_entry *re;

    FDT_RO_PROBE(fdt);
    re = fdt_mem_rsv(fdt, n);
    if (!re)
        return -FDT_ERR_BADOFFSET;

    *address = fdt64_ld(&re->address);
    *size = fdt64_ld(&re->size);
    return 0;
}

const void *
fdt_getprop_by_offset(const void *fdt, int offset,
                      const char **namep, int *lenp)
{
    const struct fdt_property *prop;

    prop = fdt_get_property_by_offset_(fdt, offset, lenp);
    if (!prop)
        return NULL;
    if (namep) {
        const char *name;
        int namelen;

        name = fdt_get_string(fdt, fdt32_ld(&prop->nameoff), &namelen);
        if (!name) {
            if (lenp)
                *lenp = namelen;
            return NULL;
        }
        *namep = name;
    }

    /* Handle realignment */
    if (fdt_version(fdt) < 0x10 &&
        (offset + sizeof(*prop)) % 8 && fdt32_ld(&prop->len) >= 8)
        return prop->data + 4;
    return prop->data;
}

const char *
fdt_get_alias_namelen(const void *fdt, const char *name, int namelen)
{
    int aliasoffset;

    aliasoffset = fdt_path_offset(fdt, "/aliases");
    if (aliasoffset < 0)
        return NULL;

    return fdt_getprop_namelen(fdt, aliasoffset, name, namelen, NULL);
}

int fdt_subnode_offset_namelen(const void *fdt, int offset,
                               const char *name, int namelen)
{
    int depth;

    FDT_RO_PROBE(fdt);

    for (depth = 0;
         (offset >= 0) && (depth >= 0);
         offset = fdt_next_node(fdt, offset, &depth))
        if ((depth == 1) && fdt_nodename_eq_(fdt, offset, name, namelen))
            return offset;

    if (depth < 0)
        return -FDT_ERR_NOTFOUND;
    return offset; /* error */
}

int fdt_path_offset_namelen(const void *fdt, const char *path, int namelen)
{
    int offset = 0;
    const char *p = path;
    const char *end = path + namelen;

    FDT_RO_PROBE(fdt);

    /* see if we have an alias */
    if (*path != '/') {
        const char *q = memchr(path, '/', end - p);

        if (!q)
            q = end;

        p = fdt_get_alias_namelen(fdt, p, q - p);
        if (!p)
            return -FDT_ERR_BADPATH;
        offset = fdt_path_offset(fdt, p);

        p = q;
    }

    while (p < end) {
        const char *q;

        while (*p == '/') {
            p++;
            if (p == end)
                return offset;
        }
        q = memchr(p, '/', end - p);
        if (! q)
            q = end;

        offset = fdt_subnode_offset_namelen(fdt, offset, p, q-p);
        if (offset < 0)
            return offset;

        p = q;
    }

    return offset;
}

int fdt_path_offset(const void *fdt, const char *path)
{
    return fdt_path_offset_namelen(fdt, path, strlen(path));
}

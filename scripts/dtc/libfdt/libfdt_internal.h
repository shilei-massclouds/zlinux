/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
#ifndef LIBFDT_INTERNAL_H
#define LIBFDT_INTERNAL_H
/*
 * libfdt - Flat Device Tree manipulation
 * Copyright (C) 2006 David Gibson, IBM Corporation.
 */
#include <fdt.h>

#define FDT_ALIGN(x, a)     (((x) + (a) - 1) & ~((a) - 1))
#define FDT_TAGALIGN(x)     (FDT_ALIGN((x), FDT_TAGSIZE))

#define FDT_SW_MAGIC        (~FDT_MAGIC)

int32_t fdt_ro_probe_(const void *fdt);
#define FDT_RO_PROBE(fdt)                   \
    {                           \
        int32_t totalsize_;             \
        if ((totalsize_ = fdt_ro_probe_(fdt)) < 0)  \
            return totalsize_;          \
    }

int32_t fdt_ro_probe_(const void *fdt);
int fdt_check_node_offset_(const void *fdt, int offset);
int fdt_check_prop_offset_(const void *fdt, int offset);

static inline const void *fdt_offset_ptr_(const void *fdt, int offset)
{
    return (const char *)fdt + fdt_off_dt_struct(fdt) + offset;
}

static inline const struct fdt_reserve_entry *
fdt_mem_rsv_(const void *fdt, int n)
{
    const struct fdt_reserve_entry *rsv_table =
        (const struct fdt_reserve_entry *)
        ((const char *)fdt + fdt_off_mem_rsvmap(fdt));

    return rsv_table + n;
}

#endif /* LIBFDT_INTERNAL_H */

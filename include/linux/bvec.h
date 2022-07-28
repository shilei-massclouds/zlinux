/* SPDX-License-Identifier: GPL-2.0 */
/*
 * bvec iterator
 *
 * Copyright (C) 2001 Ming Lei <ming.lei@canonical.com>
 */
#ifndef __LINUX_BVEC_H
#define __LINUX_BVEC_H

#include <linux/highmem.h>
#include <linux/bug.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/types.h>

struct page;

/**
 * struct bio_vec - a contiguous range of physical memory addresses
 * @bv_page:   First page associated with the address range.
 * @bv_len:    Number of bytes in the address range.
 * @bv_offset: Start of the address range relative to the start of @bv_page.
 *
 * The following holds for a bvec if n * PAGE_SIZE < bv_offset + bv_len:
 *
 *   nth_page(@bv_page, n) == @bv_page + n
 *
 * This holds because page_is_mergeable() checks the above property.
 */
struct bio_vec {
    struct page *bv_page;
    unsigned int    bv_len;
    unsigned int    bv_offset;
};

struct bvec_iter {
    sector_t            bi_sector;  /* device address in 512 byte sectors */
    unsigned int        bi_size;    /* residual I/O count */

    unsigned int        bi_idx;     /* current index into bvl_vec */

    unsigned int        bi_bvec_done;   /* number of bytes completed in
                                           current bvec */
} __packed;

/**
 * bvec_virt - return the virtual address for a bvec
 * @bvec: bvec to return the virtual address for
 *
 * Note: the caller must ensure that @bvec->bv_page is not a highmem page.
 */
static inline void *bvec_virt(struct bio_vec *bvec)
{
    WARN_ON_ONCE(PageHighMem(bvec->bv_page));
    return page_address(bvec->bv_page) + bvec->bv_offset;
}

#endif /* __LINUX_BVEC_H */

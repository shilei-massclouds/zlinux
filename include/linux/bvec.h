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

struct bvec_iter_all {
    struct bio_vec  bv;
    int             idx;
    unsigned        done;
};

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

/*
 * various member access, note that bio_data should of course not be used
 * on highmem page vectors
 */
#define __bvec_iter_bvec(bvec, iter)    (&(bvec)[(iter).bi_idx])

/* multi-page (mp_bvec) helpers */
#define mp_bvec_iter_page(bvec, iter)               \
    (__bvec_iter_bvec((bvec), (iter))->bv_page)

#define mp_bvec_iter_len(bvec, iter)                \
    min((iter).bi_size,                 \
        __bvec_iter_bvec((bvec), (iter))->bv_len - (iter).bi_bvec_done)

#define mp_bvec_iter_offset(bvec, iter)             \
    (__bvec_iter_bvec((bvec), (iter))->bv_offset + (iter).bi_bvec_done)

#define mp_bvec_iter_page_idx(bvec, iter)           \
    (mp_bvec_iter_offset((bvec), (iter)) / PAGE_SIZE)

#define mp_bvec_iter_bvec(bvec, iter)               \
((struct bio_vec) {                     \
    .bv_page    = mp_bvec_iter_page((bvec), (iter)),    \
    .bv_len     = mp_bvec_iter_len((bvec), (iter)), \
    .bv_offset  = mp_bvec_iter_offset((bvec), (iter)),  \
})

/*
 * A simpler version of bvec_iter_advance(), @bytes should not span
 * across multiple bvec entries, i.e. bytes <= bv[i->bi_idx].bv_len
 */
static inline void bvec_iter_advance_single(const struct bio_vec *bv,
                struct bvec_iter *iter, unsigned int bytes)
{
    unsigned int done = iter->bi_bvec_done + bytes;

    if (done == bv[iter->bi_idx].bv_len) {
        done = 0;
        iter->bi_idx++;
    }
    iter->bi_bvec_done = done;
    iter->bi_size -= bytes;
}

static inline bool bvec_iter_advance(const struct bio_vec *bv,
                                     struct bvec_iter *iter, unsigned bytes)
{
    unsigned int idx = iter->bi_idx;

    if (WARN_ONCE(bytes > iter->bi_size,
                  "Attempted to advance past end of bvec iter\n")) {
        iter->bi_size = 0;
        return false;
    }

    iter->bi_size -= bytes;
    bytes += iter->bi_bvec_done;

    while (bytes && bytes >= bv[idx].bv_len) {
        bytes -= bv[idx].bv_len;
        idx++;
    }

    iter->bi_idx = idx;
    iter->bi_bvec_done = bytes;
    return true;
}

static inline struct bio_vec *bvec_init_iter_all(struct bvec_iter_all *iter_all)
{
    iter_all->done = 0;
    iter_all->idx = 0;

    return &iter_all->bv;
}

static inline void bvec_advance(const struct bio_vec *bvec,
                                struct bvec_iter_all *iter_all)
{
    struct bio_vec *bv = &iter_all->bv;

    if (iter_all->done) {
        bv->bv_page++;
        bv->bv_offset = 0;
    } else {
        bv->bv_page = bvec->bv_page + (bvec->bv_offset >> PAGE_SHIFT);
        bv->bv_offset = bvec->bv_offset & ~PAGE_MASK;
    }
    bv->bv_len = min_t(unsigned int, PAGE_SIZE - bv->bv_offset,
                       bvec->bv_len - iter_all->done);
    iter_all->done += bv->bv_len;

    if (iter_all->done == bvec->bv_len) {
        iter_all->idx++;
        iter_all->done = 0;
    }
}

#endif /* __LINUX_BVEC_H */

/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *  Berkeley style UIO structures   -   Alan Cox 1994.
 */
#ifndef __LINUX_UIO_H
#define __LINUX_UIO_H

#include <linux/kernel.h>
#include <linux/thread_info.h>
#include <linux/mm_types.h>
#include <uapi/linux/uio.h>

struct page;
struct pipe_inode_info;

struct kvec {
    void *iov_base; /* and that should *never* hold a userland pointer */
    size_t iov_len;
};

enum iter_type {
    /* iter types */
    ITER_IOVEC,
    ITER_KVEC,
    ITER_BVEC,
    ITER_PIPE,
    ITER_XARRAY,
    ITER_DISCARD,
};

struct iov_iter {
    u8 iter_type;
    bool nofault;
    bool data_source;
    size_t iov_offset;
    size_t count;
    union {
        const struct iovec *iov;
        const struct kvec *kvec;
        const struct bio_vec *bvec;
        struct xarray *xarray;
        struct pipe_inode_info *pipe;
    };
    union {
        unsigned long nr_segs;
        struct {
            unsigned int head;
            unsigned int start_head;
        };
        loff_t xarray_start;
    };
};

size_t iov_iter_zero(size_t bytes, struct iov_iter *);
unsigned long iov_iter_alignment(const struct iov_iter *i);
unsigned long iov_iter_gap_alignment(const struct iov_iter *i);
void iov_iter_init(struct iov_iter *i, unsigned int direction,
                   const struct iovec *iov,
                   unsigned long nr_segs, size_t count);
void iov_iter_kvec(struct iov_iter *i, unsigned int direction,
                   const struct kvec *kvec,
                   unsigned long nr_segs, size_t count);
void iov_iter_bvec(struct iov_iter *i, unsigned int direction,
                   const struct bio_vec *bvec,
                   unsigned long nr_segs, size_t count);
void iov_iter_pipe(struct iov_iter *i, unsigned int direction,
                   struct pipe_inode_info *pipe, size_t count);
void iov_iter_discard(struct iov_iter *i, unsigned int direction, size_t count);
void iov_iter_xarray(struct iov_iter *i, unsigned int direction,
                     struct xarray *xarray, loff_t start, size_t count);
ssize_t iov_iter_get_pages(struct iov_iter *i, struct page **pages,
                           size_t maxsize, unsigned maxpages, size_t *start);
ssize_t iov_iter_get_pages_alloc(struct iov_iter *i, struct page ***pages,
                                 size_t maxsize, size_t *start);
int iov_iter_npages(const struct iov_iter *i, int maxpages);
void iov_iter_restore(struct iov_iter *i, struct iov_iter_state *state);

static inline size_t iov_iter_count(const struct iov_iter *i)
{
    return i->count;
}

/*
 * Cap the iov_iter by given limit; note that the second argument is
 * *not* the new size - it's upper limit for such.  Passing it a value
 * greater than the amount of data in iov_iter is fine - it'll just do
 * nothing in that case.
 */
static inline void iov_iter_truncate(struct iov_iter *i, u64 count)
{
    /*
     * count doesn't have to fit in size_t - comparison extends both
     * operands to u64 here and any value that would be truncated by
     * conversion in assignement is by definition greater than all
     * values of size_t, including old i->count.
     */
    if (i->count > count)
        i->count = count;
}

#endif /* __LINUX_UIO_H */

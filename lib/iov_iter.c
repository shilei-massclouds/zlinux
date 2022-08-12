// SPDX-License-Identifier: GPL-2.0-only
//#include <crypto/hash.h>
#include <linux/export.h>
#include <linux/bvec.h>
//#include <linux/fault-inject-usercopy.h>
#include <linux/uio.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#if 0
#include <linux/splice.h>
#include <net/checksum.h>
#include <linux/instrumented.h>
#endif
#include <linux/compat.h>
#include <linux/scatterlist.h>

/* covers iovec and kvec alike */
#define iterate_iovec(i, n, base, len, off, __p, STEP) {    \
    size_t off = 0;                     \
    size_t skip = i->iov_offset;                \
    do {                            \
        len = min(n, __p->iov_len - skip);      \
        if (likely(len)) {              \
            base = __p->iov_base + skip;        \
            len -= (STEP);              \
            off += len;             \
            skip += len;                \
            n -= len;               \
            if (skip < __p->iov_len)        \
                break;              \
        }                       \
        __p++;                      \
        skip = 0;                   \
    } while (n);                        \
    i->iov_offset = skip;                   \
    n = off;                        \
}

#define iterate_bvec(i, n, base, len, off, p, STEP) {       \
    size_t off = 0;                     \
    unsigned skip = i->iov_offset;              \
    while (n) {                     \
        unsigned offset = p->bv_offset + skip;      \
        unsigned left;                  \
        void *kaddr = kmap_local_page(p->bv_page +  \
                    offset / PAGE_SIZE);    \
        base = kaddr + offset % PAGE_SIZE;      \
        len = min(min(n, (size_t)(p->bv_len - skip)),   \
             (size_t)(PAGE_SIZE - offset % PAGE_SIZE)); \
        left = (STEP);                  \
        kunmap_local(kaddr);                \
        len -= left;                    \
        off += len;                 \
        skip += len;                    \
        if (skip == p->bv_len) {            \
            skip = 0;               \
            p++;                    \
        }                       \
        n -= len;                   \
        if (left)                   \
            break;                  \
    }                           \
    i->iov_offset = skip;                   \
    n = off;                        \
}

#define iterate_xarray(i, n, base, len, __off, STEP) {      \
    __label__ __out;                    \
    size_t __off = 0;                   \
    struct folio *folio;                    \
    loff_t start = i->xarray_start + i->iov_offset;     \
    pgoff_t index = start / PAGE_SIZE;          \
    XA_STATE(xas, i->xarray, index);            \
                                \
    len = PAGE_SIZE - offset_in_page(start);        \
    rcu_read_lock();                    \
    xas_for_each(&xas, folio, ULONG_MAX) {          \
        unsigned left;                  \
        size_t offset;                  \
        if (xas_retry(&xas, folio))         \
            continue;               \
        if (WARN_ON(xa_is_value(folio)))        \
            break;                  \
        if (WARN_ON(folio_test_hugetlb(folio)))     \
            break;                  \
        offset = offset_in_folio(folio, start + __off); \
        while (offset < folio_size(folio)) {        \
            base = kmap_local_folio(folio, offset); \
            len = min(n, len);          \
            left = (STEP);              \
            kunmap_local(base);         \
            len -= left;                \
            __off += len;               \
            n -= len;               \
            if (left || n == 0)         \
                goto __out;         \
            offset += len;              \
            len = PAGE_SIZE;            \
        }                       \
    }                           \
__out:                              \
    rcu_read_unlock();                  \
    i->iov_offset += __off;                 \
    n = __off;                      \
}

#define __iterate_and_advance(i, n, base, len, off, I, K) { \
    if (unlikely(i->count < n))             \
        n = i->count;                   \
    if (likely(n)) {                    \
        if (likely(iter_is_iovec(i))) {         \
            const struct iovec *iov = i->iov;   \
            void __user *base;          \
            size_t len;             \
            iterate_iovec(i, n, base, len, off, \
                        iov, (I))   \
            i->nr_segs -= iov - i->iov;     \
            i->iov = iov;               \
        } else if (iov_iter_is_bvec(i)) {       \
            const struct bio_vec *bvec = i->bvec;   \
            void *base;             \
            size_t len;             \
            iterate_bvec(i, n, base, len, off,  \
                        bvec, (K))  \
            i->nr_segs -= bvec - i->bvec;       \
            i->bvec = bvec;             \
        } else if (iov_iter_is_kvec(i)) {       \
            const struct kvec *kvec = i->kvec;  \
            void *base;             \
            size_t len;             \
            iterate_iovec(i, n, base, len, off, \
                        kvec, (K))  \
            i->nr_segs -= kvec - i->kvec;       \
            i->kvec = kvec;             \
        } else if (iov_iter_is_xarray(i)) {     \
            void *base;             \
            size_t len;             \
            iterate_xarray(i, n, base, len, off,    \
                            (K))    \
        }                       \
        i->count -= n;                  \
    }                           \
}
#define iterate_and_advance(i, n, base, len, off, I, K) \
    __iterate_and_advance(i, n, base, len, off, I, ((void)(K),0))

static int copyout(void __user *to, const void *from, size_t n)
{
    if (access_ok(to, n)) {
        n = raw_copy_to_user(to, from, n);
    }
    return n;
}

void iov_iter_kvec(struct iov_iter *i, unsigned int direction,
                   const struct kvec *kvec, unsigned long nr_segs,
                   size_t count)
{
    WARN_ON(direction & ~(READ | WRITE));
    *i = (struct iov_iter){
        .iter_type = ITER_KVEC,
        .data_source = direction,
        .kvec = kvec,
        .nr_segs = nr_segs,
        .iov_offset = 0,
        .count = count
    };
}
EXPORT_SYMBOL(iov_iter_kvec);

static inline bool page_copy_sane(struct page *page, size_t offset, size_t n)
{
    struct page *head;
    size_t v = n + offset;

    /*
     * The general case needs to access the page order in order
     * to compute the page size.
     * However, we mostly deal with order-0 pages and thus can
     * avoid a possible cache line miss for requests that fit all
     * page orders.
     */
    if (n <= v && v <= PAGE_SIZE)
        return true;

    head = compound_head(page);
    v += (page - head) << PAGE_SHIFT;

    if (likely(n <= v && v <= (page_size(head))))
        return true;
    WARN_ON(1);
    return false;
}

static size_t
copy_page_to_iter_iovec(struct page *page, size_t offset, size_t bytes,
                        struct iov_iter *i)
{
    panic("%s: END!\n", __func__);
}

static size_t copy_pipe_to_iter(const void *addr, size_t bytes,
                                struct iov_iter *i)
{
    panic("%s: END!\n", __func__);
}

size_t _copy_to_iter(const void *addr, size_t bytes, struct iov_iter *i)
{
    if (unlikely(iov_iter_is_pipe(i)))
        return copy_pipe_to_iter(addr, bytes, i);
#if 0
    if (iter_is_iovec(i))
        might_fault();
#endif
    iterate_and_advance(i, bytes, base, len, off,
                        copyout(base, addr + off, len),
                        memcpy(base, addr + off, len)
    )

    return bytes;
}
EXPORT_SYMBOL(_copy_to_iter);

static size_t
__copy_page_to_iter(struct page *page, size_t offset, size_t bytes,
                    struct iov_iter *i)
{
    if (likely(iter_is_iovec(i)))
        return copy_page_to_iter_iovec(page, offset, bytes, i);
    if (iov_iter_is_bvec(i) || iov_iter_is_kvec(i) || iov_iter_is_xarray(i)) {
        void *kaddr = kmap_local_page(page);
        size_t wanted = _copy_to_iter(kaddr + offset, bytes, i);
        kunmap_local(kaddr);
        return wanted;
    }

    panic("%s: END!\n", __func__);
}

size_t copy_page_to_iter(struct page *page, size_t offset, size_t bytes,
                         struct iov_iter *i)
{
    size_t res = 0;
    if (unlikely(!page_copy_sane(page, offset, bytes)))
        return 0;
    page += offset / PAGE_SIZE; // first subpage
    offset %= PAGE_SIZE;
    while (1) {
        size_t n = __copy_page_to_iter(page, offset,
                                       min(bytes, (size_t)PAGE_SIZE - offset),
                                       i);
        res += n;
        bytes -= n;
        if (!bytes || !n)
            break;
        offset += n;
        if (offset == PAGE_SIZE) {
            page++;
            offset = 0;
        }
    }
    return res;
}
EXPORT_SYMBOL(copy_page_to_iter);

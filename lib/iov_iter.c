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

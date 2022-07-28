/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCATTERLIST_H
#define _LINUX_SCATTERLIST_H

#include <linux/string.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <asm/io.h>

/*
 * The maximum number of SG segments that we will put inside a
 * scatterlist (unless chaining is used). Should ideally fit inside a
 * single page, to avoid a higher order allocation.  We could define this
 * to SG_MAX_SINGLE_ALLOC to pack correctly at the highest order.  The
 * minimum value is 32
 */
#define SG_CHUNK_SIZE   128

struct scatterlist {
    unsigned long   page_link;
    unsigned int    offset;
    unsigned int    length;
    dma_addr_t      dma_address;
};

struct sg_table {
    struct scatterlist *sgl;    /* the list */
    unsigned int nents;     /* number of mapped entries */
    unsigned int orig_nents;    /* original size of list */
};

typedef struct scatterlist *(sg_alloc_fn)(unsigned int, gfp_t);
typedef void (sg_free_fn)(struct scatterlist *, unsigned int);

void __sg_free_table(struct sg_table *, unsigned int, unsigned int,
                     sg_free_fn *, unsigned int);
void sg_free_table(struct sg_table *);
void sg_free_append_table(struct sg_append_table *sgt);
int __sg_alloc_table(struct sg_table *, unsigned int, unsigned int,
                     struct scatterlist *, unsigned int, gfp_t, sg_alloc_fn *);
int sg_alloc_table(struct sg_table *, unsigned int, gfp_t);

void sg_free_table_chained(struct sg_table *table, unsigned nents_first_chunk);
int sg_alloc_table_chained(struct sg_table *table, int nents,
                           struct scatterlist *first_chunk,
                           unsigned nents_first_chunk);

#endif /* _LINUX_SCATTERLIST_H */

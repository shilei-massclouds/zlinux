/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCATTERLIST_H
#define _LINUX_SCATTERLIST_H

#include <linux/string.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/mm.h>
#include <asm/io.h>

/*
 * Notes on SG table design.
 *
 * We use the unsigned long page_link field in the scatterlist struct to place
 * the page pointer AND encode information about the sg table as well. The two
 * lower bits are reserved for this information.
 *
 * If bit 0 is set, then the page_link contains a pointer to the next sg
 * table list. Otherwise the next entry is at sg + 1.
 *
 * If bit 1 is set, then this sg entry is the last element in a list.
 *
 * See sg_next().
 *
 */

#define SG_CHAIN    0x01UL
#define SG_END      0x02UL

/*
 * We overload the LSB of the page pointer to indicate whether it's
 * a valid sg entry, or whether it points to the start of a new scatterlist.
 * Those low bits are there for everyone! (thanks mason :-)
 */
#define SG_PAGE_LINK_MASK (SG_CHAIN | SG_END)

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

void sg_init_table(struct scatterlist *, unsigned int);
void sg_init_one(struct scatterlist *, const void *, unsigned int);

/**
 * sg_mark_end - Mark the end of the scatterlist
 * @sg:      SG entryScatterlist
 *
 * Description:
 *   Marks the passed in sg entry as the termination point for the sg
 *   table. A call to sg_next() on this entry will return NULL.
 *
 **/
static inline void sg_mark_end(struct scatterlist *sg)
{
    /*
     * Set termination bit, clear potential chain bit
     */
    sg->page_link |= SG_END;
    sg->page_link &= ~SG_CHAIN;
}

/**
 * sg_init_marker - Initialize markers in sg table
 * @sgl:       The SG table
 * @nents:     Number of entries in table
 *
 **/
static inline void sg_init_marker(struct scatterlist *sgl, unsigned int nents)
{
    sg_mark_end(&sgl[nents - 1]);
}

/**
 * sg_assign_page - Assign a given page to an SG entry
 * @sg:         SG entry
 * @page:       The page
 *
 * Description:
 *   Assign page to sg entry. Also see sg_set_page(), the most commonly used
 *   variant.
 *
 **/
static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
{
    unsigned long page_link = sg->page_link & (SG_CHAIN | SG_END);

    /*
     * In order for the low bit stealing approach to work, pages
     * must be aligned at a 32-bit boundary as a minimum.
     */
    BUG_ON((unsigned long)page & SG_PAGE_LINK_MASK);
    sg->page_link = page_link | (unsigned long) page;
}

/**
 * sg_set_page - Set sg entry to point at given page
 * @sg:      SG entry
 * @page:    The page
 * @len:     Length of data
 * @offset:  Offset into page
 *
 * Description:
 *   Use this function to set an sg entry pointing at a page, never assign
 *   the page directly. We encode sg table information in the lower bits
 *   of the page pointer. See sg_page() for looking up the page belonging
 *   to an sg entry.
 *
 **/
static inline void sg_set_page(struct scatterlist *sg, struct page *page,
                               unsigned int len, unsigned int offset)
{
    sg_assign_page(sg, page);
    sg->offset = offset;
    sg->length = len;
}

/**
 * sg_unmark_end - Undo setting the end of the scatterlist
 * @sg:      SG entryScatterlist
 *
 * Description:
 *   Removes the termination marker from the given entry of the scatterlist.
 *
 **/
static inline void sg_unmark_end(struct scatterlist *sg)
{
    sg->page_link &= ~SG_END;
}

struct scatterlist *sg_next(struct scatterlist *);
struct scatterlist *sg_last(struct scatterlist *s, unsigned int);

static inline unsigned int __sg_flags(struct scatterlist *sg)
{
    return sg->page_link & SG_PAGE_LINK_MASK;
}

static inline struct scatterlist *sg_chain_ptr(struct scatterlist *sg)
{
    return (struct scatterlist *)(sg->page_link & ~SG_PAGE_LINK_MASK);
}

static inline bool sg_is_chain(struct scatterlist *sg)
{
    return __sg_flags(sg) & SG_CHAIN;
}

static inline bool sg_is_last(struct scatterlist *sg)
{
    return __sg_flags(sg) & SG_END;
}

/**
 * sg_set_buf - Set sg entry to point at given data
 * @sg:      SG entry
 * @buf:     Data
 * @buflen:  Data length
 *
 **/
static inline void sg_set_buf(struct scatterlist *sg, const void *buf,
                              unsigned int buflen)
{
    sg_set_page(sg, virt_to_page(buf), buflen, offset_in_page(buf));
}

static inline struct page *sg_page(struct scatterlist *sg)
{
    return (struct page *)((sg)->page_link & ~SG_PAGE_LINK_MASK);
}

/**
 * sg_phys - Return physical address of an sg entry
 * @sg:      SG entry
 *
 * Description:
 *   This calls page_to_phys() on the page in this sg entry, and adds the
 *   sg offset. The caller must know that it is legal to call page_to_phys()
 *   on the sg page.
 *
 **/
static inline dma_addr_t sg_phys(struct scatterlist *sg)
{
    return page_to_phys(sg_page(sg)) + sg->offset;
}

#endif /* _LINUX_SCATTERLIST_H */

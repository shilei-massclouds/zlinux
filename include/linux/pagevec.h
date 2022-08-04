/* SPDX-License-Identifier: GPL-2.0 */
/*
 * include/linux/pagevec.h
 *
 * In many places it is efficient to batch an operation up against multiple
 * pages.  A pagevec is a multipage container which is used for that.
 */

#ifndef _LINUX_PAGEVEC_H
#define _LINUX_PAGEVEC_H

#include <linux/xarray.h>

/* 15 pointers + header align the pagevec structure to a power of two */
#define PAGEVEC_SIZE    15

struct page;
struct folio;
struct address_space;

/* Layout must match folio_batch */
struct pagevec {
    unsigned char nr;
    bool percpu_pvec_drained;
    struct page *pages[PAGEVEC_SIZE];
};

static inline void pagevec_init(struct pagevec *pvec)
{
    pvec->nr = 0;
    pvec->percpu_pvec_drained = false;
}

static inline void pagevec_reinit(struct pagevec *pvec)
{
    pvec->nr = 0;
}

static inline unsigned pagevec_count(struct pagevec *pvec)
{
    return pvec->nr;
}

static inline unsigned pagevec_space(struct pagevec *pvec)
{
    return PAGEVEC_SIZE - pvec->nr;
}

/*
 * Add a page to a pagevec.  Returns the number of slots still available.
 */
static inline unsigned pagevec_add(struct pagevec *pvec, struct page *page)
{
    pvec->pages[pvec->nr++] = page;
    return pagevec_space(pvec);
}

unsigned pagevec_lookup_range_tag(struct pagevec *pvec,
                                  struct address_space *mapping,
                                  pgoff_t *index, pgoff_t end, xa_mark_t tag);

static inline
unsigned pagevec_lookup_tag(struct pagevec *pvec, struct address_space *mapping,
                            pgoff_t *index, xa_mark_t tag)
{
    return pagevec_lookup_range_tag(pvec, mapping, index, (pgoff_t)-1, tag);
}

#endif /* _LINUX_PAGEVEC_H */

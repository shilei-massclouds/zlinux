/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/log2.h>
#include <linux/page-flags-layout.h>

#define _struct_page_alignment

struct page {
    unsigned long flags;    /* Atomic flags, some possibly updated asynchronously */

    union {
        struct {    /* Page cache and anonymous pages */
            /**
             * @lru: Pageout list, eg. active_list protected by
             * lruvec->lru_lock.  Sometimes used as a generic list
             * by the page owner.
             */
            struct list_head lru;
            pgoff_t index;      /* Our offset within mapping. */
            /**
             * @private: Mapping-private opaque data.
             * Usually used for buffer_heads if PagePrivate.
             * Used for swp_entry_t if PageSwapCache.
             * Indicates order in the buddy system if PageBuddy.
             */
            unsigned long private;
        };
        struct {    /* Tail pages of compound page */
            unsigned long compound_head;    /* Bit zero is set */
        };
    };

    union {     /* This union is 4 bytes in size. */
        /*
         * If the page can be mapped to userspace, encodes the number
         * of times this page is referenced by a page table.
         */
        atomic_t _mapcount;

        /*
         * If the page is neither PageSlab nor mappable to userspace,
         * the value stored here may help determine what this page
         * is used for.  See page-flags.h for a list of page types
         * which are currently stored here.
         */
        unsigned int page_type;

        unsigned int active;        /* SLAB */
        int units;                  /* SLOB */
    };

    /* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
    atomic_t _refcount;

} _struct_page_alignment;

/**
 * struct folio - Represents a contiguous set of bytes.
 * @flags: Identical to the page flags.
 * @lru: Least Recently Used list; tracks how recently this folio was used.
 * @mapping: The file this page belongs to, or refers to the anon_vma for
 *    anonymous memory.
 * @index: Offset within the file, in units of pages.  For anonymous memory,
 *    this is the index from the beginning of the mmap.
 * @private: Filesystem per-folio data (see folio_attach_private()).
 *    Used for swp_entry_t if folio_test_swapcache().
 * @_mapcount: Do not access this member directly.  Use folio_mapcount() to
 *    find out how many times this folio is mapped by userspace.
 * @_refcount: Do not access this member directly.  Use folio_ref_count()
 *    to find how many references there are to this folio.
 * @memcg_data: Memory Control Group data.
 *
 * A folio is a physically, virtually and logically contiguous set
 * of bytes.  It is a power-of-two in size, and it is aligned to that
 * same power-of-two.  It is at least as large as %PAGE_SIZE.  If it is
 * in the page cache, it is at a file offset which is a multiple of that
 * power-of-two.  It may be mapped into userspace at an address which is
 * at an arbitrary page offset, but its kernel virtual address is aligned
 * to its size.
 */
struct folio {
    /* private: don't document the anon union */
    union {
        struct {
    /* public: */
            unsigned long flags;
            struct list_head lru;
            struct address_space *mapping;
            pgoff_t index;
            void *private;
            atomic_t _mapcount;
            atomic_t _refcount;
    /* private: the union with struct page is transitional */
        };
        struct page page;
    };
};

/*
 * Used for sizing the vmemmap region on some architectures
 */
#define STRUCT_PAGE_MAX_SHIFT   (order_base_2(sizeof(struct page)))

struct mm_struct {
};

extern struct mm_struct init_mm;

/*
 * page_private can be used on tail pages.  However, PagePrivate is only
 * checked by the VM on the head page.  So page_private on the tail pages
 * should be used for data that's ancillary to the head page (eg attaching
 * buffer heads to tail pages after attaching buffer heads to the head page)
 */
#define page_private(page)      ((page)->private)

static inline void
set_page_private(struct page *page, unsigned long private)
{
    page->private = private;
}

#endif /* _LINUX_MM_TYPES_H */

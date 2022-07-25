/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGEMAP_H
#define _LINUX_PAGEMAP_H

/*
 * Copyright 1995 Linus Torvalds
 */
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/highmem.h>
#include <linux/compiler.h>
#include <linux/uaccess.h>
#include <linux/gfp.h>
#include <linux/bitops.h>
#include <linux/hardirq.h> /* for in_interrupt() */
#if 0
#include <linux/hugetlb_inline.h>
#endif

struct folio_batch;

#define VM_READAHEAD_PAGES  (SZ_128K / PAGE_SIZE)

#define FGP_ACCESSED    0x00000001
#define FGP_LOCK        0x00000002
#define FGP_CREAT       0x00000004
#define FGP_WRITE       0x00000008
#define FGP_NOFS        0x00000010
#define FGP_NOWAIT      0x00000020
#define FGP_FOR_MMAP    0x00000040
#define FGP_HEAD        0x00000080
#define FGP_ENTRY       0x00000100
#define FGP_STABLE      0x00000200

/*
 * Bits in mapping->flags.
 */
enum mapping_flags {
    AS_EIO          = 0,    /* IO error on async write */
    AS_ENOSPC       = 1,    /* ENOSPC on async write */
    AS_MM_ALL_LOCKS = 2,    /* under mm_take_all_locks() */
    AS_UNEVICTABLE  = 3,    /* e.g., ramdisk, SHM_LOCK */
    AS_EXITING      = 4,    /* final truncate in progress */
    /* writeback related tags are not used */
    AS_NO_WRITEBACK_TAGS = 5,
    AS_LARGE_FOLIO_SUPPORT = 6,
};

typedef int filler_t(void *, struct page *);

/**
 * mapping_set_large_folios() - Indicate the file supports large folios.
 * @mapping: The file.
 *
 * The filesystem should call this function in its inode constructor to
 * indicate that the VFS can use large folios to cache the contents of
 * the file.
 *
 * Context: This should not be called while the inode is active as it
 * is non-atomic.
 */
static inline void mapping_set_large_folios(struct address_space *mapping)
{
    __set_bit(AS_LARGE_FOLIO_SUPPORT, &mapping->flags);
}

bool noop_dirty_folio(struct address_space *mapping, struct folio *folio);

/*
 * This is non-atomic.  Only to be used before the mapping is activated.
 * Probably needs a barrier...
 */
static inline void mapping_set_gfp_mask(struct address_space *m, gfp_t mask)
{
    m->gfp_mask = mask;
}

static inline void mapping_set_unevictable(struct address_space *mapping)
{
    set_bit(AS_UNEVICTABLE, &mapping->flags);
}

int filemap_write_and_wait_range(struct address_space *mapping,
                                 loff_t lstart, loff_t lend);

static inline int filemap_write_and_wait(struct address_space *mapping)
{
    return filemap_write_and_wait_range(mapping, 0, LLONG_MAX);
}

struct page *read_cache_page(struct address_space *, pgoff_t index,
                             filler_t *filler, void *data);

static inline struct page *
read_mapping_page(struct address_space *mapping,
                  pgoff_t index, struct file *file)
{
    return read_cache_page(mapping, index, NULL, file);
}

static inline gfp_t mapping_gfp_mask(struct address_space * mapping)
{
    return mapping->gfp_mask;
}

struct folio *
__filemap_get_folio(struct address_space *mapping, pgoff_t index,
                    int fgp_flags, gfp_t gfp);

/**
 * filemap_get_folio - Find and get a folio.
 * @mapping: The address_space to search.
 * @index: The page index.
 *
 * Looks up the page cache entry at @mapping & @index.  If a folio is
 * present, it is returned with an increased refcount.
 *
 * Otherwise, %NULL is returned.
 */
static inline struct folio *
filemap_get_folio(struct address_space *mapping, pgoff_t index)
{
    return __filemap_get_folio(mapping, index, 0, 0);
}

static inline struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
{
    return folio_alloc(gfp, order);
}

/* Must be non-static for BPF error injection */
int __filemap_add_folio(struct address_space *mapping, struct folio *folio,
                        pgoff_t index, gfp_t gfp, void **shadowp);

#endif /* _LINUX_PAGEMAP_H */

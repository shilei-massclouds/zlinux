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

struct wait_page_queue {
    struct folio *folio;
    int bit_nr;
    wait_queue_entry_t wait;
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

/**
 * folio_attach_private - Attach private data to a folio.
 * @folio: Folio to attach data to.
 * @data: Data to attach to folio.
 *
 * Attaching private data to a folio increments the page's reference count.
 * The data must be detached before the folio will be freed.
 */
static inline void folio_attach_private(struct folio *folio, void *data)
{
    folio_get(folio);
    folio->private = data;
    folio_set_private(folio);
}

/**
 * folio_change_private - Change private data on a folio.
 * @folio: Folio to change the data on.
 * @data: Data to set on the folio.
 *
 * Change the private data attached to a folio and return the old
 * data.  The page must previously have had data attached and the data
 * must be detached before the folio will be freed.
 *
 * Return: Data that was previously attached to the folio.
 */
static inline void *folio_change_private(struct folio *folio, void *data)
{
    void *old = folio_get_private(folio);

    folio->private = data;
    return old;
}

/**
 * folio_detach_private - Detach private data from a folio.
 * @folio: Folio to detach data from.
 *
 * Removes the data that was previously attached to the folio and decrements
 * the refcount on the page.
 *
 * Return: Data that was attached to the folio.
 */
static inline void *folio_detach_private(struct folio *folio)
{
    void *data = folio_get_private(folio);

    if (!folio_test_private(folio))
        return NULL;
    folio_clear_private(folio);
    folio->private = NULL;
    folio_put(folio);

    return data;
}

static inline void attach_page_private(struct page *page, void *data)
{
    folio_attach_private(page_folio(page), data);
}

void folio_unlock(struct folio *folio);

void unlock_page(struct page *page);

/*
 * This is exported only for folio_wait_locked/folio_wait_writeback, etc.,
 * and should not be used directly.
 */
void folio_wait_bit(struct folio *folio, int bit_nr);
int folio_wait_bit_killable(struct folio *folio, int bit_nr);

/*
 * Wait for a folio to be unlocked.
 *
 * This must be called with the caller "holding" the folio,
 * ie with increased "page->count" so that the folio won't
 * go away during the wait..
 */
static inline void folio_wait_locked(struct folio *folio)
{
    if (folio_test_locked(folio))
        folio_wait_bit(folio, PG_locked);
}

/**
 * folio_file_page - The page for a particular index.
 * @folio: The folio which contains this index.
 * @index: The index we want to look up.
 *
 * Sometimes after looking up a folio in the page cache, we need to
 * obtain the specific page for an index (eg a page fault).
 *
 * Return: The page containing the file data for this index.
 */
static inline struct page *folio_file_page(struct folio *folio, pgoff_t index)
{
    /* HugeTLBfs indexes the page cache in units of hpage_size */
    if (folio_test_hugetlb(folio))
        return &folio->page;
    return folio_page(folio, index & (folio_nr_pages(folio) - 1));
}

#define swapcache_index(folio)  __page_file_index(&(folio)->page)

/**
 * folio_index - File index of a folio.
 * @folio: The folio.
 *
 * For a folio which is either in the page cache or the swap cache,
 * return its index within the address_space it belongs to.  If you know
 * the page is definitely in the page cache, you can look at the folio's
 * index directly.
 *
 * Return: The index (offset in units of pages) of a folio in its file.
 */
static inline pgoff_t folio_index(struct folio *folio)
{
    if (unlikely(folio_test_swapcache(folio))) {
        //return swapcache_index(folio);
        panic("%s: END!\n", __func__);
    }
    return folio->index;
}

/**
 * folio_contains - Does this folio contain this index?
 * @folio: The folio.
 * @index: The page index within the file.
 *
 * Context: The caller should have the page locked in order to prevent
 * (eg) shmem from moving the page between the page cache and swap cache
 * and changing its index in the middle of the operation.
 * Return: true or false.
 */
static inline bool folio_contains(struct folio *folio, pgoff_t index)
{
    /* HugeTLBfs indexes the page cache in units of hpage_size */
    if (folio_test_hugetlb(folio))
        return folio->index == index;
    return index - folio_index(folio) < folio_nr_pages(folio);
}

static inline bool folio_trylock(struct folio *folio)
{
    return likely(!test_and_set_bit_lock(PG_locked, folio_flags(folio, 0)));
}

void __folio_lock(struct folio *folio);

static inline void folio_lock(struct folio *folio)
{
    might_sleep();
    if (!folio_trylock(folio))
        __folio_lock(folio);
}

/**
 * folio_inode - Get the host inode for this folio.
 * @folio: The folio.
 *
 * For folios which are in the page cache, return the inode that this folio
 * belongs to.
 *
 * Do not call this for folios which aren't in the page cache.
 */
static inline struct inode *folio_inode(struct folio *folio)
{
    return folio->mapping->host;
}

void folio_wait_stable(struct folio *folio);

static inline bool mapping_empty(struct address_space *mapping)
{
    return xa_empty(&mapping->i_pages);
}

unsigned find_get_pages_range_tag(struct address_space *mapping,
                                  pgoff_t *index, pgoff_t end, xa_mark_t tag,
                                  unsigned int nr_pages, struct page **pages);

struct page *pagecache_get_page(struct address_space *mapping, pgoff_t index,
                                int fgp_flags, gfp_t gfp);

static inline
struct page *find_get_page_flags(struct address_space *mapping,
                                 pgoff_t offset, int fgp_flags)
{
    return pagecache_get_page(mapping, offset, fgp_flags, 0);
}

/* Restricts the given gfp_mask to what the mapping allows. */
static inline gfp_t mapping_gfp_constraint(struct address_space *mapping,
                                           gfp_t gfp_mask)
{
    return mapping_gfp_mask(mapping) & gfp_mask;
}

/**
 * find_or_create_page - locate or add a pagecache page
 * @mapping: the page's address_space
 * @index: the page's index into the mapping
 * @gfp_mask: page allocation mode
 *
 * Looks up the page cache slot at @mapping & @offset.  If there is a
 * page cache page, it is returned locked and with an increased
 * refcount.
 *
 * If the page is not present, a new page is allocated using @gfp_mask
 * and added to the page cache and the VM's LRU list.  The page is
 * returned locked and with an increased refcount.
 *
 * On memory exhaustion, %NULL is returned.
 *
 * find_or_create_page() may sleep, even if @gfp_flags specifies an
 * atomic allocation!
 */
static inline
struct page *find_or_create_page(struct address_space *mapping,
                                 pgoff_t index, gfp_t gfp_mask)
{
    return pagecache_get_page(mapping, index, FGP_LOCK|FGP_ACCESSED|FGP_CREAT,
                              gfp_mask);
}

static inline void *detach_page_private(struct page *page)
{
    return folio_detach_private(page_folio(page));
}

void __folio_cancel_dirty(struct folio *folio);

static inline void folio_cancel_dirty(struct folio *folio)
{
    /* Avoid atomic ops, locking, etc. when not actually needed. */
    if (folio_test_dirty(folio))
        __folio_cancel_dirty(folio);
}

static inline void cancel_dirty_page(struct page *page)
{
    folio_cancel_dirty(page_folio(page));
}

#endif /* _LINUX_PAGEMAP_H */

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
#include <linux/hugetlb_inline.h>

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

struct wait_page_key {
    struct folio *folio;
    int bit_nr;
    int page_match;
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

bool filemap_release_folio(struct folio *folio, gfp_t gfp);

void delete_from_page_cache_batch(struct address_space *mapping,
                                  struct folio_batch *fbatch);

void folio_account_cleaned(struct folio *folio, struct bdi_writeback *wb);

/*
 * mapping_shrinkable - test if page cache state allows inode reclaim
 * @mapping: the page cache mapping
 *
 * This checks the mapping's cache state for the pupose of inode
 * reclaim and LRU management.
 *
 * The caller is expected to hold the i_lock, but is not required to
 * hold the i_pages lock, which usually protects cache state. That's
 * because the i_lock and the list_lru lock that protect the inode and
 * its LRU state don't nest inside the irq-safe i_pages lock.
 *
 * Cache deletions are performed under the i_lock, which ensures that
 * when an inode goes empty, it will reliably get queued on the LRU.
 *
 * Cache additions do not acquire the i_lock and may race with this
 * check, in which case we'll report the inode as shrinkable when it
 * has cache pages. This is okay: the shrinker also checks the
 * refcount and the referenced bit, which will be elevated or set in
 * the process of adding new cache pages to an inode.
 */
static inline bool mapping_shrinkable(struct address_space *mapping)
{
    void *head;

    /* Cache completely empty? Shrink away. */
    head = rcu_access_pointer(mapping->i_pages.xa_head);
    if (!head)
        return true;

    /*
     * The xarray stores single offset-0 entries directly in the
     * head pointer, which allows non-resident page cache entries
     * to escape the shadow shrinker's list of xarray nodes. The
     * inode shrinker needs to pick them up under memory pressure.
     */
    if (!xa_is_node(head) && xa_is_value(head))
        return true;

    return false;
}

static inline pgoff_t linear_page_index(struct vm_area_struct *vma,
                                        unsigned long address)
{
    pgoff_t pgoff;
    if (unlikely(is_vm_hugetlb_page(vma))) {
        //return linear_hugepage_index(vma, address);
        panic("%s: END!\n", __func__);
    }
    pgoff = (address - vma->vm_start) >> PAGE_SHIFT;
    pgoff += vma->vm_pgoff;
    return pgoff;
}

static inline unsigned long dir_pages(struct inode *inode)
{
    return (unsigned long)(inode->i_size + PAGE_SIZE - 1) >> PAGE_SHIFT;
}

void end_page_writeback(struct page *page);

/**
 * mapping_set_error - record a writeback error in the address_space
 * @mapping: the mapping in which an error should be set
 * @error: the error to set in the mapping
 *
 * When writeback fails in some way, we must record that error so that
 * userspace can be informed when fsync and the like are called.  We endeavor
 * to report errors on any file that was open at the time of the error.  Some
 * internal callers also need to know when writeback errors have occurred.
 *
 * When a writeback error occurs, most filesystems will want to call
 * mapping_set_error to record the error in the mapping so that it can be
 * reported when the application calls fsync(2).
 */
static inline void mapping_set_error(struct address_space *mapping, int error)
{
    panic("%s: END!\n", __func__);
}

struct address_space *folio_mapping(struct folio *);
struct address_space *page_mapping(struct page *);

void folio_end_writeback(struct folio *folio);

void page_endio(struct page *page, bool is_write, int err);

/**
 * struct readahead_control - Describes a readahead request.
 *
 * A readahead request is for consecutive pages.  Filesystems which
 * implement the ->readahead method should call readahead_page() or
 * readahead_page_batch() in a loop and attempt to start I/O against
 * each page in the request.
 *
 * Most of the fields in this struct are private and should be accessed
 * by the functions below.
 *
 * @file: The file, used primarily by network filesystems for authentication.
 *    May be NULL if invoked internally by the filesystem.
 * @mapping: Readahead this filesystem object.
 * @ra: File readahead state.  May be NULL.
 */
struct readahead_control {
    struct file *file;
    struct address_space *mapping;
    struct file_ra_state *ra;
/* private: use the readahead_* accessors instead */
    pgoff_t _index;
    unsigned int _nr_pages;
    unsigned int _batch_count;
};

#define DEFINE_READAHEAD(ractl, f, r, m, i) \
    struct readahead_control ractl = {      \
        .file = f,                          \
        .mapping = m,                       \
        .ra = r,                            \
        ._index = i,                        \
    }

void page_cache_ra_unbounded(struct readahead_control *,
                             unsigned long nr_to_read,
                             unsigned long lookahead_count);
void page_cache_sync_ra(struct readahead_control *, unsigned long req_count);
void page_cache_async_ra(struct readahead_control *, struct folio *,
                         unsigned long req_count);
void readahead_expand(struct readahead_control *ractl,
                      loff_t new_start, size_t new_len);

/**
 * page_cache_sync_readahead - generic file readahead
 * @mapping: address_space which holds the pagecache and I/O vectors
 * @ra: file_ra_state which holds the readahead state
 * @file: Used by the filesystem for authentication.
 * @index: Index of first page to be read.
 * @req_count: Total number of pages being read by the caller.
 *
 * page_cache_sync_readahead() should be called when a cache miss happened:
 * it will submit the read.  The readahead logic may decide to piggyback more
 * pages onto the read request if access patterns suggest it will improve
 * performance.
 */
static inline
void page_cache_sync_readahead(struct address_space *mapping,
                               struct file_ra_state *ra, struct file *file,
                               pgoff_t index, unsigned long req_count)
{
    DEFINE_READAHEAD(ractl, file, ra, mapping, index);
    page_cache_sync_ra(&ractl, req_count);
}

/**
 * readahead_index - The index of the first page in this readahead request.
 * @rac: The readahead request.
 */
static inline pgoff_t readahead_index(struct readahead_control *rac)
{
    return rac->_index;
}

static inline gfp_t readahead_gfp_mask(struct address_space *x)
{
    return mapping_gfp_mask(x) | __GFP_NORETRY | __GFP_NOWARN;
}

/*
 * Large folio support currently depends on THP.  These dependencies are
 * being worked on but are not yet fixed.
 */
static inline bool mapping_large_folio_support(struct address_space *mapping)
{
    return false;
}

int add_to_page_cache_locked(struct page *page, struct address_space *mapping,
                             pgoff_t index, gfp_t gfp);
int add_to_page_cache_lru(struct page *page, struct address_space *mapping,
                          pgoff_t index, gfp_t gfp);
int filemap_add_folio(struct address_space *mapping, struct folio *folio,
                      pgoff_t index, gfp_t gfp);
void filemap_remove_folio(struct folio *folio);
void delete_from_page_cache(struct page *page);
void __filemap_remove_folio(struct folio *folio, void *shadow);

/**
 * readahead_count - The number of pages in this readahead request.
 * @rac: The readahead request.
 */
static inline unsigned int readahead_count(struct readahead_control *rac)
{
    return rac->_nr_pages;
}

static inline struct folio *__readahead_folio(struct readahead_control *ractl)
{
    struct folio *folio;

    BUG_ON(ractl->_batch_count > ractl->_nr_pages);
    ractl->_nr_pages -= ractl->_batch_count;
    ractl->_index += ractl->_batch_count;

    if (!ractl->_nr_pages) {
        ractl->_batch_count = 0;
        return NULL;
    }

    folio = xa_load(&ractl->mapping->i_pages, ractl->_index);
    VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
    ractl->_batch_count = folio_nr_pages(folio);

    return folio;
}

/**
 * readahead_page - Get the next page to read.
 * @ractl: The current readahead request.
 *
 * Context: The page is locked and has an elevated refcount.  The caller
 * should decreases the refcount once the page has been submitted for I/O
 * and unlock the page once all I/O to that page has completed.
 * Return: A pointer to the next page, or %NULL if we are done.
 */
static inline struct page *readahead_page(struct readahead_control *ractl)
{
    struct folio *folio = __readahead_folio(ractl);

    return &folio->page;
}

static inline bool mapping_unevictable(struct address_space *mapping)
{
    return mapping && test_bit(AS_UNEVICTABLE, &mapping->flags);
}

/*
 * Return byte-offset into filesystem object for page.
 */
static inline loff_t page_offset(struct page *page)
{
    return ((loff_t)page->index) << PAGE_SHIFT;
}

/**
 * folio_pos - Returns the byte position of this folio in its file.
 * @folio: The folio.
 */
static inline loff_t folio_pos(struct folio *folio)
{
    return page_offset(&folio->page);
}

/*
 * lock_page may only be called if we have the page's inode pinned.
 */
static inline void lock_page(struct page *page)
{
    struct folio *folio;
    might_sleep();

    folio = page_folio(page);
    if (!folio_trylock(folio))
        __folio_lock(folio);
}

pgoff_t page_cache_next_miss(struct address_space *mapping,
                             pgoff_t index, unsigned long max_scan);
pgoff_t page_cache_prev_miss(struct address_space *mapping,
                             pgoff_t index, unsigned long max_scan);

/*
 * Return true if the page was successfully locked
 */
static inline int trylock_page(struct page *page)
{
    return folio_trylock(page_folio(page));
}

int write_inode_now(struct inode *, int sync);

static inline void mapping_set_exiting(struct address_space *mapping)
{
    set_bit(AS_EXITING, &mapping->flags);
}

static inline bool wake_page_match(struct wait_page_queue *wait_page,
                                   struct wait_page_key *key)
{
    if (wait_page->folio != key->folio)
        return false;
    key->page_match = 1;

    if (wait_page->bit_nr != key->bit_nr)
        return false;

    return true;
}

void release_pages(struct page **pages, int nr);

static inline int mapping_exiting(struct address_space *mapping)
{
    return test_bit(AS_EXITING, &mapping->flags);
}

extern pgoff_t hugetlb_basepage_index(struct page *page);

/*
 * Get the offset in PAGE_SIZE (even for hugetlb folios).
 * (TODO: hugetlb folios should have ->index in PAGE_SIZE)
 */
static inline pgoff_t folio_pgoff(struct folio *folio)
{
    if (unlikely(folio_test_hugetlb(folio)))
        return hugetlb_basepage_index(&folio->page);
    return folio->index;
}

/*
 * Get index of the page within radix-tree (but not for hugetlb pages).
 * (TODO: remove once hugetlb pages will have ->index in PAGE_SIZE)
 */
static inline pgoff_t page_to_index(struct page *page)
{
    struct page *head;

    if (likely(!PageTransTail(page)))
        return page->index;

    head = compound_head(page);
    /*
     *  We don't initialize ->index for tail pages: calculate based on
     *  head page
     */
    return head->index + page - head;
}

/*
 * Get the offset in PAGE_SIZE (even for hugetlb pages).
 * (TODO: hugetlb pages should have ->index in PAGE_SIZE)
 */
static inline pgoff_t page_to_pgoff(struct page *page)
{
    if (unlikely(PageHuge(page)))
        return hugetlb_basepage_index(page);
    return page_to_index(page);
}

int try_to_release_page(struct page *page, gfp_t gfp);

#endif /* _LINUX_PAGEMAP_H */

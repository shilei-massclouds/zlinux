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

#endif /* _LINUX_PAGEMAP_H */

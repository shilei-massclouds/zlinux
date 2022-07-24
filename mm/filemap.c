// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/mm/filemap.c
 *
 * Copyright (C) 1994-1999  Linus Torvalds
 */

/*
 * This file handles the generic file mmap semantics used by
 * most "normal" filesystems (but you don't /have/ to use this:
 * the NFS filesystem used to do this differently, for example)
 */
#include <linux/export.h>
#include <linux/compiler.h>
//#include <linux/dax.h>
#include <linux/fs.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
//#include <linux/capability.h>
#include <linux/kernel_stat.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#if 0
#include <linux/swapops.h>
#include <linux/mman.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/error-injection.h>
#endif
#include <linux/hash.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
#if 0
#include <linux/pagevec.h>
#include <linux/security.h>
#include <linux/cpuset.h>
#include <linux/hugetlb.h>
#include <linux/memcontrol.h>
#include <linux/rmap.h>
#include <linux/delayacct.h>
#include <linux/psi.h>
#include <linux/page_idle.h>
#endif
#include <linux/shmem_fs.h>
#include <linux/ramfs.h>
#if 0
#include <linux/migrate.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#endif
#include "internal.h"

/*
 * FIXME: remove all knowledge of the buffer layer from the core VM
 */
#if 0
#include <linux/buffer_head.h> /* for try_to_free_buffers */

#include <asm/mman.h>
#endif

vm_fault_t filemap_map_pages(struct vm_fault *vmf,
                             pgoff_t start_pgoff, pgoff_t end_pgoff)
{
    panic("%s: END!\n", __func__);
}

/* This is used for a general mmap of a disk file */

int generic_file_mmap(struct file *file, struct vm_area_struct *vma)
{
#if 0
    struct address_space *mapping = file->f_mapping;

    if (!mapping->a_ops->readpage)
        return -ENOEXEC;
    file_accessed(file);
    vma->vm_ops = &generic_file_vm_ops;
#endif
    panic("%s: END!\n", __func__);
    return 0;
}
EXPORT_SYMBOL(generic_file_mmap);

/* Returns true if writeback might be needed or already in progress. */
static bool mapping_needs_writeback(struct address_space *mapping)
{
    return mapping->nrpages;
}

int filemap_check_errors(struct address_space *mapping)
{
    int ret = 0;
    /* Check for outstanding write errors */
    if (test_bit(AS_ENOSPC, &mapping->flags) &&
        test_and_clear_bit(AS_ENOSPC, &mapping->flags))
        ret = -ENOSPC;
    if (test_bit(AS_EIO, &mapping->flags) &&
        test_and_clear_bit(AS_EIO, &mapping->flags))
        ret = -EIO;
    return ret;
}
EXPORT_SYMBOL(filemap_check_errors);

int filemap_write_and_wait_range(struct address_space *mapping,
                                 loff_t lstart, loff_t lend)
{
    int err = 0;

    if (mapping_needs_writeback(mapping)) {
        panic("%s: mapping_needs_writeback!\n", __func__);
    } else {
        err = filemap_check_errors(mapping);
    }
    return err;
}
EXPORT_SYMBOL(filemap_write_and_wait_range);

static struct page *
do_read_cache_page(struct address_space *mapping,
                   pgoff_t index, filler_t *filler, void *data, gfp_t gfp)
{
    struct folio *folio;

#if 0
    folio = do_read_cache_folio(mapping, index, filler, data, gfp);
    if (IS_ERR(folio))
        return &folio->page;
    return folio_file_page(folio, index);
#endif
    panic("%s: END!\n", __func__);
}

struct page *read_cache_page(struct address_space *mapping,
                             pgoff_t index, filler_t *filler, void *data)
{
    return do_read_cache_page(mapping, index, filler, data,
                              mapping_gfp_mask(mapping));
}
EXPORT_SYMBOL(read_cache_page);

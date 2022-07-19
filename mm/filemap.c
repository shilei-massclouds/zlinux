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

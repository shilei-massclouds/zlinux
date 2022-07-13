// SPDX-License-Identifier: GPL-2.0-only
/*
 * fs/dcache.c
 *
 * Complete reimplementation
 * (C) 1997 Thomas Schoebel-Theuer,
 * with heavy changes by Linus Torvalds
 */

/*
 * Notes on the allocation strategy:
 *
 * The dcache is a master of the icache - whenever a dcache entry
 * exists, the inode will always exist. "iput()" is done either when
 * the dcache entry is deleted or garbage collected.
 */

//#include <linux/ratelimit.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/fs.h>
#if 0
#include <linux/fscrypt.h>
#include <linux/fsnotify.h>
#endif
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/export.h>
//#include <linux/security.h>
#include <linux/seqlock.h>
#include <linux/memblock.h>
#if 0
#include <linux/bit_spinlock.h>
#include <linux/rculist_bl.h>
#endif
#include <linux/list_lru.h>
#include "internal.h"
#if 0
#include "mount.h"
#endif

/* SLAB cache for __getname() consumers */
struct kmem_cache *names_cachep __read_mostly;
EXPORT_SYMBOL(names_cachep);

void __init vfs_caches_init(void)
{
    names_cachep =
        kmem_cache_create_usercopy("names_cache", PATH_MAX, 0,
                                   SLAB_HWCACHE_ALIGN|SLAB_PANIC,
                                   0, PATH_MAX, NULL);

#if 0
    dcache_init();
    inode_init();
    files_init();
    files_maxfiles_init();
    mnt_init();
#endif
    bdev_cache_init();
#if 0
    chrdev_init();
#endif
}

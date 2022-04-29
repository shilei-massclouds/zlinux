// SPDX-License-Identifier: GPL-2.0

#include    <linux/slab.h>
#include    <linux/mm.h>
#include    <linux/poison.h>
//#include    <linux/swap.h>
#include    <linux/cache.h>
//#include    <linux/interrupt.h>
#include    <linux/init.h>
#include    <linux/compiler.h>
//#include    <linux/cpuset.h>
/*
#include    <linux/proc_fs.h>
#include    <linux/seq_file.h>
#include    <linux/notifier.h>
#include    <linux/kallsyms.h>
*/
#include    <linux/cpu.h>
//#include    <linux/sysctl.h>
#include    <linux/module.h>
/*
#include    <linux/rcupdate.h>
#include    <linux/string.h>
#include    <linux/uaccess.h>
#include    <linux/nodemask.h>
#include    <linux/kmemleak.h>
#include    <linux/mempolicy.h>
#include    <linux/mutex.h>
#include    <linux/fault-inject.h>
#include    <linux/rtmutex.h>
#include    <linux/reciprocal_div.h>
#include    <linux/debugobjects.h>
#include    <linux/memory.h>
#include    <linux/prefetch.h>
#include    <linux/sched/task_stack.h>
*/

/*
#include    <net/sock.h>

#include    <asm/cacheflush.h>
*/
#include    <asm/tlbflush.h>
#include    <asm/page.h>

//#include <trace/events/kmem.h>

#include    "internal.h"

#include    "slab.h"

void *kmem_cache_alloc(struct kmem_cache *cachep, gfp_t flags)
{
#if 0
    void *ret = slab_alloc(cachep, flags, _RET_IP_);

    trace_kmem_cache_alloc(_RET_IP_, ret,
                           cachep->object_size, cachep->size, flags);

    return ret;
#endif
    panic("%s: NOT-implemented!", __func__);
    return NULL;
}
EXPORT_SYMBOL(kmem_cache_alloc);

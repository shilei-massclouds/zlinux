/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_MM_H
#define _LINUX_SCHED_MM_H

#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/gfp.h>
//#include <linux/sync_core.h>

/*
 * Applies per-task gfp context to the given allocation flags.
 * PF_MEMALLOC_NOIO implies GFP_NOIO
 * PF_MEMALLOC_NOFS implies GFP_NOFS
 * PF_MEMALLOC_PIN  implies !GFP_MOVABLE
 */
static inline gfp_t current_gfp_context(gfp_t flags)
{
    unsigned int pflags = READ_ONCE(current->flags);

    if (unlikely(pflags & (PF_MEMALLOC_NOIO | PF_MEMALLOC_NOFS | PF_MEMALLOC_PIN))) {
        /*
         * NOIO implies both NOIO and NOFS and it is a weaker context
         * so always make sure it makes precedence
         */
        if (pflags & PF_MEMALLOC_NOIO)
            flags &= ~(__GFP_IO | __GFP_FS);
        else if (pflags & PF_MEMALLOC_NOFS)
            flags &= ~__GFP_FS;

        if (pflags & PF_MEMALLOC_PIN)
            flags &= ~__GFP_MOVABLE;
    }
    return flags;
}

#endif /* _LINUX_SCHED_MM_H */

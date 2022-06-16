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

/**
 * memalloc_noio_save - Marks implicit GFP_NOIO allocation scope.
 *
 * This functions marks the beginning of the GFP_NOIO allocation scope.
 * All further allocations will implicitly drop __GFP_IO flag and so
 * they are safe for the IO critical section from the allocation recursion
 * point of view. Use memalloc_noio_restore to end the scope with flags
 * returned by this function.
 *
 * This function is safe to be used from any context.
 */
static inline unsigned int memalloc_noio_save(void)
{
    unsigned int flags = current->flags & PF_MEMALLOC_NOIO;
    current->flags |= PF_MEMALLOC_NOIO;
    return flags;
}

/**
 * memalloc_noio_restore - Ends the implicit GFP_NOIO scope.
 * @flags: Flags to restore.
 *
 * Ends the implicit GFP_NOIO scope started by memalloc_noio_save function.
 * Always make sure that the given flags is the return value from the
 * pairing memalloc_noio_save call.
 */
static inline void memalloc_noio_restore(unsigned int flags)
{
    current->flags = (current->flags & ~PF_MEMALLOC_NOIO) | flags;
}

/**
 * memalloc_nofs_save - Marks implicit GFP_NOFS allocation scope.
 *
 * This functions marks the beginning of the GFP_NOFS allocation scope.
 * All further allocations will implicitly drop __GFP_FS flag and so
 * they are safe for the FS critical section from the allocation recursion
 * point of view. Use memalloc_nofs_restore to end the scope with flags
 * returned by this function.
 *
 * This function is safe to be used from any context.
 */
static inline unsigned int memalloc_nofs_save(void)
{
    unsigned int flags = current->flags & PF_MEMALLOC_NOFS;
    current->flags |= PF_MEMALLOC_NOFS;
    return flags;
}

/**
 * memalloc_nofs_restore - Ends the implicit GFP_NOFS scope.
 * @flags: Flags to restore.
 *
 * Ends the implicit GFP_NOFS scope started by memalloc_nofs_save function.
 * Always make sure that the given flags is the return value from the
 * pairing memalloc_nofs_save call.
 */
static inline void memalloc_nofs_restore(unsigned int flags)
{
    current->flags = (current->flags & ~PF_MEMALLOC_NOFS) | flags;
}

#endif /* _LINUX_SCHED_MM_H */

#ifndef _LINUX_MMAP_LOCK_H
#define _LINUX_MMAP_LOCK_H

#include <linux/lockdep.h>
#include <linux/mm_types.h>
#include <linux/mmdebug.h>
#include <linux/rwsem.h>
//#include <linux/tracepoint-defs.h>
#include <linux/types.h>

static inline void mmap_init_lock(struct mm_struct *mm)
{
    init_rwsem(&mm->mmap_lock);
}

#endif /* _LINUX_MMAP_LOCK_H */

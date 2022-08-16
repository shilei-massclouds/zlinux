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

static inline int mmap_write_lock_killable(struct mm_struct *mm)
{
    int ret;

    ret = down_write_killable(&mm->mmap_lock);
    return ret;
}

static inline void mmap_write_unlock(struct mm_struct *mm)
{
    up_write(&mm->mmap_lock);
}

static inline void mmap_assert_locked(struct mm_struct *mm)
{
    VM_BUG_ON_MM(!rwsem_is_locked(&mm->mmap_lock), mm);
}

static inline void mmap_read_lock(struct mm_struct *mm)
{
    down_read(&mm->mmap_lock);
}

static inline void mmap_read_unlock(struct mm_struct *mm)
{
    up_read(&mm->mmap_lock);
}

static inline int mmap_read_lock_killable(struct mm_struct *mm)
{
    int ret;

    ret = down_read_killable(&mm->mmap_lock);
    return ret;
}

#endif /* _LINUX_MMAP_LOCK_H */

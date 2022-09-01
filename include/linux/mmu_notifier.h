/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MMU_NOTIFIER_H
#define _LINUX_MMU_NOTIFIER_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm_types.h>
#include <linux/mmap_lock.h>
#include <linux/srcu.h>
//#include <linux/interval_tree.h>

struct mmu_notifier_subscriptions;
struct mmu_notifier;
struct mmu_notifier_range;
struct mmu_interval_notifier;

#define MMU_NOTIFIER_RANGE_BLOCKABLE (1 << 0)

struct mmu_notifier_ops {
    /*
     * Called either by mmu_notifier_unregister or when the mm is
     * being destroyed by exit_mmap, always before all pages are
     * freed. This can run concurrently with other mmu notifier
     * methods (the ones invoked outside the mm context) and it
     * should tear down all secondary mmu mappings and freeze the
     * secondary mmu. If this method isn't implemented you've to
     * be sure that nothing could possibly write to the pages
     * through the secondary mmu by the time the last thread with
     * tsk->mm == mm exits.
     *
     * As side note: the pages freed after ->release returns could
     * be immediately reallocated by the gart at an alias physical
     * address with a different cache model, so if ->release isn't
     * implemented because all _software_ driven memory accesses
     * through the secondary mmu are terminated by the time the
     * last thread of this mm quits, you've also to be sure that
     * speculative _hardware_ operations can't allocate dirty
     * cachelines in the cpu that could not be snooped and made
     * coherent with the other read and write operations happening
     * through the gart alias address, so leading to memory
     * corruption.
     */
    void (*release)(struct mmu_notifier *subscription,
            struct mm_struct *mm);

    /*
     * clear_flush_young is called after the VM is
     * test-and-clearing the young/accessed bitflag in the
     * pte. This way the VM will provide proper aging to the
     * accesses to the page through the secondary MMUs and not
     * only to the ones through the Linux pte.
     * Start-end is necessary in case the secondary MMU is mapping the page
     * at a smaller granularity than the primary MMU.
     */
    int (*clear_flush_young)(struct mmu_notifier *subscription,
                 struct mm_struct *mm,
                 unsigned long start,
                 unsigned long end);

    /*
     * clear_young is a lightweight version of clear_flush_young. Like the
     * latter, it is supposed to test-and-clear the young/accessed bitflag
     * in the secondary pte, but it may omit flushing the secondary tlb.
     */
    int (*clear_young)(struct mmu_notifier *subscription,
               struct mm_struct *mm,
               unsigned long start,
               unsigned long end);


    /*
     * test_young is called to check the young/accessed bitflag in
     * the secondary pte. This is used to know if the page is
     * frequently used without actually clearing the flag or tearing
     * down the secondary mapping on the page.
     */
    int (*test_young)(struct mmu_notifier *subscription,
              struct mm_struct *mm,
              unsigned long address);

    /*
     * change_pte is called in cases that pte mapping to page is changed:
     * for example, when ksm remaps pte to point to a new shared page.
     */
    void (*change_pte)(struct mmu_notifier *subscription,
               struct mm_struct *mm,
               unsigned long address,
               pte_t pte);
    /*
     * invalidate_range_start() and invalidate_range_end() must be
     * paired and are called only when the mmap_lock and/or the
     * locks protecting the reverse maps are held. If the subsystem
     * can't guarantee that no additional references are taken to
     * the pages in the range, it has to implement the
     * invalidate_range() notifier to remove any references taken
     * after invalidate_range_start().
     *
     * Invalidation of multiple concurrent ranges may be
     * optionally permitted by the driver. Either way the
     * establishment of sptes is forbidden in the range passed to
     * invalidate_range_begin/end for the whole duration of the
     * invalidate_range_begin/end critical section.
     *
     * invalidate_range_start() is called when all pages in the
     * range are still mapped and have at least a refcount of one.
     *
     * invalidate_range_end() is called when all pages in the
     * range have been unmapped and the pages have been freed by
     * the VM.
     *
     * The VM will remove the page table entries and potentially
     * the page between invalidate_range_start() and
     * invalidate_range_end(). If the page must not be freed
     * because of pending I/O or other circumstances then the
     * invalidate_range_start() callback (or the initial mapping
     * by the driver) must make sure that the refcount is kept
     * elevated.
     *
     * If the driver increases the refcount when the pages are
     * initially mapped into an address space then either
     * invalidate_range_start() or invalidate_range_end() may
     * decrease the refcount. If the refcount is decreased on
     * invalidate_range_start() then the VM can free pages as page
     * table entries are removed.  If the refcount is only
     * dropped on invalidate_range_end() then the driver itself
     * will drop the last refcount but it must take care to flush
     * any secondary tlb before doing the final free on the
     * page. Pages will no longer be referenced by the linux
     * address space but may still be referenced by sptes until
     * the last refcount is dropped.
     *
     * If blockable argument is set to false then the callback cannot
     * sleep and has to return with -EAGAIN if sleeping would be required.
     * 0 should be returned otherwise. Please note that notifiers that can
     * fail invalidate_range_start are not allowed to implement
     * invalidate_range_end, as there is no mechanism for informing the
     * notifier that its start failed.
     */
    int (*invalidate_range_start)(struct mmu_notifier *subscription,
                      const struct mmu_notifier_range *range);
    void (*invalidate_range_end)(struct mmu_notifier *subscription,
                     const struct mmu_notifier_range *range);

    /*
     * invalidate_range() is either called between
     * invalidate_range_start() and invalidate_range_end() when the
     * VM has to free pages that where unmapped, but before the
     * pages are actually freed, or outside of _start()/_end() when
     * a (remote) TLB is necessary.
     *
     * If invalidate_range() is used to manage a non-CPU TLB with
     * shared page-tables, it not necessary to implement the
     * invalidate_range_start()/end() notifiers, as
     * invalidate_range() already catches the points in time when an
     * external TLB range needs to be flushed. For more in depth
     * discussion on this see Documentation/vm/mmu_notifier.rst
     *
     * Note that this function might be called with just a sub-range
     * of what was passed to invalidate_range_start()/end(), if
     * called between those functions.
     */
    void (*invalidate_range)(struct mmu_notifier *subscription,
                 struct mm_struct *mm,
                 unsigned long start,
                 unsigned long end);

    /*
     * These callbacks are used with the get/put interface to manage the
     * lifetime of the mmu_notifier memory. alloc_notifier() returns a new
     * notifier for use with the mm.
     *
     * free_notifier() is only called after the mmu_notifier has been
     * fully put, calls to any ops callback are prevented and no ops
     * callbacks are currently running. It is called from a SRCU callback
     * and cannot sleep.
     */
    struct mmu_notifier *(*alloc_notifier)(struct mm_struct *mm);
    void (*free_notifier)(struct mmu_notifier *subscription);
};

/*
 * The notifier chains are protected by mmap_lock and/or the reverse map
 * semaphores. Notifier chains are only changed when all reverse maps and
 * the mmap_lock locks are taken.
 *
 * Therefore notifier chains can only be traversed when either
 *
 * 1. mmap_lock is held.
 * 2. One of the reverse map locks is held (i_mmap_rwsem or anon_vma->rwsem).
 * 3. No other concurrent thread can access the list (release)
 */
struct mmu_notifier {
    struct hlist_node hlist;
    const struct mmu_notifier_ops *ops;
    struct mm_struct *mm;
    struct rcu_head rcu;
    unsigned int users;
};

/**
 * enum mmu_notifier_event - reason for the mmu notifier callback
 * @MMU_NOTIFY_UNMAP: either munmap() that unmap the range or a mremap() that
 * move the range
 *
 * @MMU_NOTIFY_CLEAR: clear page table entry (many reasons for this like
 * madvise() or replacing a page by another one, ...).
 *
 * @MMU_NOTIFY_PROTECTION_VMA: update is due to protection change for the range
 * ie using the vma access permission (vm_page_prot) to update the whole range
 * is enough no need to inspect changes to the CPU page table (mprotect()
 * syscall)
 *
 * @MMU_NOTIFY_PROTECTION_PAGE: update is due to change in read/write flag for
 * pages in the range so to mirror those changes the user must inspect the CPU
 * page table (from the end callback).
 *
 * @MMU_NOTIFY_SOFT_DIRTY: soft dirty accounting (still same page and same
 * access flags). User should soft dirty the page in the end callback to make
 * sure that anyone relying on soft dirtiness catch pages that might be written
 * through non CPU mappings.
 *
 * @MMU_NOTIFY_RELEASE: used during mmu_interval_notifier invalidate to signal
 * that the mm refcount is zero and the range is no longer accessible.
 *
 * @MMU_NOTIFY_MIGRATE: used during migrate_vma_collect() invalidate to signal
 * a device driver to possibly ignore the invalidation if the
 * owner field matches the driver's device private pgmap owner.
 *
 * @MMU_NOTIFY_EXCLUSIVE: to signal a device driver that the device will no
 * longer have exclusive access to the page. When sent during creation of an
 * exclusive range the owner will be initialised to the value provided by the
 * caller of make_device_exclusive_range(), otherwise the owner will be NULL.
 */
enum mmu_notifier_event {
    MMU_NOTIFY_UNMAP = 0,
    MMU_NOTIFY_CLEAR,
    MMU_NOTIFY_PROTECTION_VMA,
    MMU_NOTIFY_PROTECTION_PAGE,
    MMU_NOTIFY_SOFT_DIRTY,
    MMU_NOTIFY_RELEASE,
    MMU_NOTIFY_MIGRATE,
    MMU_NOTIFY_EXCLUSIVE,
};

struct mmu_notifier_range {
    struct vm_area_struct *vma;
    struct mm_struct *mm;
    unsigned long start;
    unsigned long end;
    unsigned flags;
    enum mmu_notifier_event event;
    void *owner;
};

extern int __mmu_notifier_clear_flush_young(struct mm_struct *mm,
                                            unsigned long start,
                                            unsigned long end);

static inline int mm_has_notifiers(struct mm_struct *mm)
{
    return unlikely(mm->notifier_subscriptions);
}

#define ptep_clear_flush_young_notify(__vma, __address, __ptep)     \
({                                  \
    int __young;                            \
    struct vm_area_struct *___vma = __vma;              \
    unsigned long ___address = __address;               \
    __young = ptep_clear_flush_young(___vma, ___address, __ptep);   \
    __young |= mmu_notifier_clear_flush_young(___vma->vm_mm,    \
                          ___address,       \
                          ___address +      \
                            PAGE_SIZE); \
    __young;                            \
})

static inline int mmu_notifier_clear_flush_young(struct mm_struct *mm,
                                                 unsigned long start,
                                                 unsigned long end)
{
    if (mm_has_notifiers(mm))
        return __mmu_notifier_clear_flush_young(mm, start, end);
    return 0;
}

static inline void
mmu_notifier_range_init(struct mmu_notifier_range *range,
                        enum mmu_notifier_event event,
                        unsigned flags,
                        struct vm_area_struct *vma,
                        struct mm_struct *mm,
                        unsigned long start,
                        unsigned long end)
{
    range->vma = vma;
    range->event = event;
    range->mm = mm;
    range->start = start;
    range->end = end;
    range->flags = flags;
}

extern int __mmu_notifier_invalidate_range_start(struct mmu_notifier_range *r);

static inline void
mmu_notifier_invalidate_range_start(struct mmu_notifier_range *range)
{
    might_sleep();

    if (mm_has_notifiers(range->mm)) {
        range->flags |= MMU_NOTIFIER_RANGE_BLOCKABLE;
        __mmu_notifier_invalidate_range_start(range);
    }
}

#endif /* _LINUX_MMU_NOTIFIER_H */

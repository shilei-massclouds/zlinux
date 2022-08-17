// SPDX-License-Identifier: GPL-2.0-only
/*
 * mm/mmap.c
 *
 * Written by obz.
 *
 * Address space accounting code    <alan@lxorguk.ukuu.org.uk>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/backing-dev.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/vmacache.h>
#if 0
#include <linux/shm.h>
#endif
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#if 0
#include <linux/capability.h>
#endif
#include <linux/init.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/hugetlb.h>
#include <linux/shmem_fs.h>
//#include <linux/profile.h>
#include <linux/export.h>
#include <linux/mount.h>
//#include <linux/mempolicy.h>
#include <linux/rmap.h>
#if 0
#include <linux/mmu_notifier.h>
#endif
#include <linux/mmdebug.h>
#if 0
#include <linux/perf_event.h>
#include <linux/audit.h>
#include <linux/khugepaged.h>
#include <linux/uprobes.h>
#endif
#include <linux/rbtree_augmented.h>
//#include <linux/notifier.h>
//#include <linux/memory.h>
#include <linux/printk.h>
//#include <linux/userfaultfd_k.h>
#include <linux/moduleparam.h>
//#include <linux/pkeys.h>
//#include <linux/oom.h>
#include <linux/sched/mm.h>
#include <linux/security.h>

#include <linux/uaccess.h>
#include <asm/cacheflush.h>
//#include <asm/tlb.h>
#include <asm/mmu_context.h>

#include "internal.h"

static bool ignore_rlimit_data;

/* enforced gap between the expanding stack and other mappings. */
unsigned long stack_guard_gap = 256UL<<PAGE_SHIFT;

#define validate_mm_rb(root, ignore) do { } while (0)
#define validate_mm(mm) do { } while (0)

static inline unsigned long vma_compute_gap(struct vm_area_struct *vma)
{
    unsigned long gap, prev_end;

    /*
     * Note: in the rare case of a VM_GROWSDOWN above a VM_GROWSUP, we
     * allow two stack_guard_gaps between them here, and when choosing
     * an unmapped area; whereas when expanding we only require one.
     * That's a little inconsistent, but keeps the code here simpler.
     */
    gap = vm_start_gap(vma);
    if (vma->vm_prev) {
        prev_end = vm_end_gap(vma->vm_prev);
        if (gap > prev_end)
            gap -= prev_end;
        else
            gap = 0;
    }
    return gap;
}

RB_DECLARE_CALLBACKS_MAX(static, vma_gap_callbacks,
                         struct vm_area_struct, vm_rb,
                         unsigned long, rb_subtree_gap, vma_compute_gap)

/*
 * Update augmented rbtree rb_subtree_gap values after vma->vm_start or
 * vma->vm_prev->vm_end values changed, without modifying the vma's position
 * in the rbtree.
 */
static void vma_gap_update(struct vm_area_struct *vma)
{
    /*
     * As it turns out, RB_DECLARE_CALLBACKS_MAX() already created
     * a callback function that does exactly what we want.
     */
    vma_gap_callbacks_propagate(&vma->vm_rb, NULL);
}

static inline void vma_rb_insert(struct vm_area_struct *vma,
                                 struct rb_root *root)
{
    /* All rb_subtree_gap values must be consistent prior to insertion */
    rb_insert_augmented(&vma->vm_rb, root, &vma_gap_callbacks);
}

/* description of effects of mapping type and prot in current implementation.
 * this is due to the limited x86 page protection hardware.  The expected
 * behavior is in parens:
 *
 * map_type prot
 *      PROT_NONE   PROT_READ   PROT_WRITE  PROT_EXEC
 * MAP_SHARED   r: (no) no  r: (yes) yes    r: (no) yes r: (no) yes
 *      w: (no) no  w: (no) no  w: (yes) yes    w: (no) no
 *      x: (no) no  x: (no) yes x: (no) yes x: (yes) yes
 *
 * MAP_PRIVATE  r: (no) no  r: (yes) yes    r: (no) yes r: (no) yes
 *      w: (no) no  w: (no) no  w: (copy) copy  w: (no) no
 *      x: (no) no  x: (no) yes x: (no) yes x: (yes) yes
 *
 * On arm64, PROT_EXEC has the following behaviour for both MAP_SHARED and
 * MAP_PRIVATE (with Enhanced PAN supported):
 *                              r: (no) no
 *                              w: (no) no
 *                              x: (yes) yes
 */
pgprot_t protection_map[16] __ro_after_init = {
    __P000, __P001, __P010, __P011, __P100, __P101, __P110, __P111,
    __S000, __S001, __S010, __S011, __S100, __S101, __S110, __S111
};

static inline pgprot_t arch_filter_pgprot(pgprot_t prot)
{
    return prot;
}

pgprot_t vm_get_page_prot(unsigned long vm_flags)
{
    pgprot_t ret = __pgprot(pgprot_val(protection_map[vm_flags &
                                       (VM_READ|VM_WRITE|VM_EXEC|VM_SHARED)]) |
                            pgprot_val(arch_vm_get_page_prot(vm_flags)));

    return arch_filter_pgprot(ret);
}
EXPORT_SYMBOL(vm_get_page_prot);

static int find_vma_links(struct mm_struct *mm, unsigned long addr,
                          unsigned long end, struct vm_area_struct **pprev,
                          struct rb_node ***rb_link, struct rb_node **rb_parent)
{
    struct rb_node **__rb_link, *__rb_parent, *rb_prev;

    mmap_assert_locked(mm);
    __rb_link = &mm->mm_rb.rb_node;
    rb_prev = __rb_parent = NULL;

    while (*__rb_link) {
        struct vm_area_struct *vma_tmp;

        __rb_parent = *__rb_link;
        vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

        if (vma_tmp->vm_end > addr) {
            /* Fail if an existing vma overlaps the area */
            if (vma_tmp->vm_start < end)
                return -ENOMEM;
            __rb_link = &__rb_parent->rb_left;
        } else {
            rb_prev = __rb_parent;
            __rb_link = &__rb_parent->rb_right;
        }
    }

    *pprev = NULL;
    if (rb_prev)
        *pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
    *rb_link = __rb_link;
    *rb_parent = __rb_parent;
    return 0;
}

void __vma_link_rb(struct mm_struct *mm, struct vm_area_struct *vma,
                   struct rb_node **rb_link, struct rb_node *rb_parent)
{
    /* Update tracking information for the gap following the new vma. */
    if (vma->vm_next)
        vma_gap_update(vma->vm_next);
    else
        mm->highest_vm_end = vm_end_gap(vma);

    /*
     * vma->vm_prev wasn't known when we followed the rbtree to find the
     * correct insertion point for that vma. As a result, we could not
     * update the vma vm_rb parents rb_subtree_gap values on the way down.
     * So, we first insert the vma with a zero rb_subtree_gap value
     * (to be consistent with what we did on the way down), and then
     * immediately update the gap to the correct value. Finally we
     * rebalance the rbtree after all augmented values have been set.
     */
    rb_link_node(&vma->vm_rb, rb_parent, rb_link);
    vma->rb_subtree_gap = 0;
    vma_gap_update(vma);
    vma_rb_insert(vma, &mm->mm_rb);
}

static void __vma_link_file(struct vm_area_struct *vma)
{
    struct file *file;

    file = vma->vm_file;
    if (file) {
        struct address_space *mapping = file->f_mapping;

        if (vma->vm_flags & VM_SHARED)
            mapping_allow_writable(mapping);

        vma_interval_tree_insert(vma, &mapping->i_mmap);
    }
}

static void
__vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
           struct vm_area_struct *prev, struct rb_node **rb_link,
           struct rb_node *rb_parent)
{
    __vma_link_list(mm, vma, prev);
    __vma_link_rb(mm, vma, rb_link, rb_parent);
}

static void vma_link(struct mm_struct *mm, struct vm_area_struct *vma,
                     struct vm_area_struct *prev, struct rb_node **rb_link,
                     struct rb_node *rb_parent)
{
    struct address_space *mapping = NULL;

    if (vma->vm_file) {
        mapping = vma->vm_file->f_mapping;
        i_mmap_lock_write(mapping);
    }

    __vma_link(mm, vma, prev, rb_link, rb_parent);
    __vma_link_file(vma);

    if (mapping)
        i_mmap_unlock_write(mapping);

    mm->map_count++;
}

/* Insert vm structure into process list sorted by address
 * and into the inode's i_mmap tree.  If vm_file is non-NULL
 * then i_mmap_rwsem is taken here.
 */
int insert_vm_struct(struct mm_struct *mm, struct vm_area_struct *vma)
{
    struct vm_area_struct *prev;
    struct rb_node **rb_link, *rb_parent;

    if (find_vma_links(mm, vma->vm_start, vma->vm_end,
                       &prev, &rb_link, &rb_parent))
        return -ENOMEM;
#if 0
    if ((vma->vm_flags & VM_ACCOUNT) &&
         security_vm_enough_memory_mm(mm, vma_pages(vma)))
        return -ENOMEM;
#endif

    /*
     * The vm_pgoff of a purely anonymous vma should be irrelevant
     * until its first write fault, when page's anon_vma and index
     * are set.  But now set the vm_pgoff it will almost certainly
     * end up with (unless mremap moves it elsewhere before that
     * first wfault), so /proc/pid/maps tells a consistent story.
     *
     * By setting it to reflect the virtual start address of the
     * vma, merges and splits can happen in a seamless way, just
     * using the existing file pgoff checks and manipulations.
     * Similarly in do_mmap and in do_brk_flags.
     */
    if (vma_is_anonymous(vma)) {
        BUG_ON(vma->anon_vma);
        vma->vm_pgoff = vma->vm_start >> PAGE_SHIFT;
    }

    vma_link(mm, vma, prev, rb_link, rb_parent);
    return 0;
}

/*
 * Return true if the calling process may expand its vm space by the passed
 * number of pages
 */
bool may_expand_vm(struct mm_struct *mm, vm_flags_t flags, unsigned long npages)
{
    if (mm->total_vm + npages > rlimit(RLIMIT_AS) >> PAGE_SHIFT)
        return false;

    if (is_data_mapping(flags) &&
        mm->data_vm + npages > rlimit(RLIMIT_DATA) >> PAGE_SHIFT) {
        /* Workaround for Valgrind */
        if (rlimit(RLIMIT_DATA) == 0 &&
            mm->data_vm + npages <= rlimit_max(RLIMIT_DATA) >> PAGE_SHIFT)
            return true;

        pr_warn_once("%s (%d): VmData %lu exceed data ulimit %lu. "
                     "Update limits%s.\n",
                     current->comm, current->pid,
                     (mm->data_vm + npages) << PAGE_SHIFT,
                     rlimit(RLIMIT_DATA),
                     ignore_rlimit_data ? "" :
                     " or use boot option ignore_rlimit_data");

        if (!ignore_rlimit_data)
            return false;
    }

    return true;
}

/*
 * Verify that the stack growth is acceptable and
 * update accounting. This is shared with both the
 * grow-up and grow-down cases.
 */
static int acct_stack_growth(struct vm_area_struct *vma,
                             unsigned long size, unsigned long grow)
{
    struct mm_struct *mm = vma->vm_mm;
    unsigned long new_start;

    /* address space limit tests */
    if (!may_expand_vm(mm, vma->vm_flags, grow))
        return -ENOMEM;

    /* Stack limit test */
    if (size > rlimit(RLIMIT_STACK))
        return -ENOMEM;

    /* mlock limit tests */
    if (vma->vm_flags & VM_LOCKED) {
        unsigned long locked;
        unsigned long limit;
        locked = mm->locked_vm + grow;
        limit = rlimit(RLIMIT_MEMLOCK);
        limit >>= PAGE_SHIFT;
        if (locked > limit)
            return -ENOMEM;
    }

    /* Check to ensure the stack will not grow into a hugetlb-only region */
    new_start = (vma->vm_flags & VM_GROWSUP) ? vma->vm_start :
        vma->vm_end - size;

#if 0
    /*
     * Overcommit..  This must be the final test, as it will
     * update security statistics.
     */
    if (security_vm_enough_memory_mm(mm, grow))
        return -ENOMEM;
#endif

    return 0;
}

void vm_stat_account(struct mm_struct *mm, vm_flags_t flags, long npages)
{
    WRITE_ONCE(mm->total_vm, READ_ONCE(mm->total_vm)+npages);

    if (is_exec_mapping(flags))
        mm->exec_vm += npages;
    else if (is_stack_mapping(flags))
        mm->stack_vm += npages;
    else if (is_data_mapping(flags))
        mm->data_vm += npages;
}

/*
 * vma has some anon_vma assigned, and is already inserted on that
 * anon_vma's interval trees.
 *
 * Before updating the vma's vm_start / vm_end / vm_pgoff fields, the
 * vma must be removed from the anon_vma's interval trees using
 * anon_vma_interval_tree_pre_update_vma().
 *
 * After the update, the vma will be reinserted using
 * anon_vma_interval_tree_post_update_vma().
 *
 * The entire update must be protected by exclusive mmap_lock and by
 * the root anon_vma's mutex.
 */
static inline void
anon_vma_interval_tree_pre_update_vma(struct vm_area_struct *vma)
{
    struct anon_vma_chain *avc;

    list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
        anon_vma_interval_tree_remove(avc, &avc->anon_vma->rb_root);
}

static inline void
anon_vma_interval_tree_post_update_vma(struct vm_area_struct *vma)
{
    struct anon_vma_chain *avc;

    list_for_each_entry(avc, &vma->anon_vma_chain, same_vma)
        anon_vma_interval_tree_insert(avc, &avc->anon_vma->rb_root);
}

/*
 * vma is the first one with address < vma->vm_start.  Have to extend vma.
 */
int expand_downwards(struct vm_area_struct *vma, unsigned long address)
{
    struct mm_struct *mm = vma->vm_mm;
    struct vm_area_struct *prev;
    int error = 0;

    address &= PAGE_MASK;
    if (address < mmap_min_addr)
        return -EPERM;

    /* Enforce stack_guard_gap */
    prev = vma->vm_prev;
    /* Check that both stack segments have the same anon_vma? */
    if (prev && !(prev->vm_flags & VM_GROWSDOWN) && vma_is_accessible(prev)) {
        if (address - prev->vm_end < stack_guard_gap)
            return -ENOMEM;
    }

    /* We must make sure the anon_vma is allocated. */
    if (unlikely(anon_vma_prepare(vma)))
        return -ENOMEM;

    /*
     * vma->vm_start/vm_end cannot change under us because the caller
     * is required to hold the mmap_lock in read mode.  We need the
     * anon_vma lock to serialize against concurrent expand_stacks.
     */
    anon_vma_lock_write(vma->anon_vma);

    /* Somebody else might have raced and expanded it already */
    if (address < vma->vm_start) {
        unsigned long size, grow;

        size = vma->vm_end - address;
        grow = (vma->vm_start - address) >> PAGE_SHIFT;

        error = -ENOMEM;
        if (grow <= vma->vm_pgoff) {
            error = acct_stack_growth(vma, size, grow);
            if (!error) {
                /*
                 * vma_gap_update() doesn't support concurrent
                 * updates, but we only hold a shared mmap_lock
                 * lock here, so we need to protect against
                 * concurrent vma expansions.
                 * anon_vma_lock_write() doesn't help here, as
                 * we don't guarantee that all growable vmas
                 * in a mm share the same root anon vma.
                 * So, we reuse mm->page_table_lock to guard
                 * against concurrent vma expansions.
                 */
                spin_lock(&mm->page_table_lock);
                if (vma->vm_flags & VM_LOCKED)
                    mm->locked_vm += grow;
                vm_stat_account(mm, vma->vm_flags, grow);
                anon_vma_interval_tree_pre_update_vma(vma);
                vma->vm_start = address;
                vma->vm_pgoff -= grow;
                anon_vma_interval_tree_post_update_vma(vma);
                vma_gap_update(vma);
                spin_unlock(&mm->page_table_lock);

                //perf_event_mmap(vma);
            }
        }
    }
    anon_vma_unlock_write(vma->anon_vma);
    validate_mm(mm);
    return error;
}

int expand_stack(struct vm_area_struct *vma, unsigned long address)
{
    return expand_downwards(vma, address);
}

/* Look up the first VMA which satisfies  addr < vm_end,  NULL if none. */
struct vm_area_struct *find_vma(struct mm_struct *mm, unsigned long addr)
{
    struct rb_node *rb_node;
    struct vm_area_struct *vma;

    mmap_assert_locked(mm);
    /* Check the cache first. */
    vma = vmacache_find(mm, addr);
    if (likely(vma))
        return vma;

    rb_node = mm->mm_rb.rb_node;

    while (rb_node) {
        struct vm_area_struct *tmp;

        tmp = rb_entry(rb_node, struct vm_area_struct, vm_rb);

        if (tmp->vm_end > addr) {
            vma = tmp;
            if (tmp->vm_start <= addr)
                break;
            rb_node = rb_node->rb_left;
        } else
            rb_node = rb_node->rb_right;
    }

    if (vma)
        vmacache_update(addr, vma);
    return vma;
}

struct vm_area_struct *
find_extend_vma(struct mm_struct *mm, unsigned long addr)
{
    struct vm_area_struct *vma;
    unsigned long start;

    addr &= PAGE_MASK;
    vma = find_vma(mm, addr);
    if (!vma)
        return NULL;
    if (vma->vm_start <= addr)
        return vma;
    if (!(vma->vm_flags & VM_GROWSDOWN))
        return NULL;
    start = vma->vm_start;
    if (expand_stack(vma, addr))
        return NULL;
    if (vma->vm_flags & VM_LOCKED)
        populate_vma_page_range(vma, addr, start, NULL);
    return vma;
}

/*
 * Rough compatibility check to quickly see if it's even worth looking
 * at sharing an anon_vma.
 *
 * They need to have the same vm_file, and the flags can only differ
 * in things that mprotect may change.
 *
 * NOTE! The fact that we share an anon_vma doesn't _have_ to mean that
 * we can merge the two vma's. For example, we refuse to merge a vma if
 * there is a vm_ops->close() function, because that indicates that the
 * driver is doing some kind of reference counting. But that doesn't
 * really matter for the anon_vma sharing case.
 */
static int
anon_vma_compatible(struct vm_area_struct *a, struct vm_area_struct *b)
{
    return a->vm_end == b->vm_start && a->vm_file == b->vm_file &&
        !((a->vm_flags ^ b->vm_flags) & ~(VM_ACCESS_FLAGS | VM_SOFTDIRTY)) &&
        b->vm_pgoff == a->vm_pgoff + ((b->vm_start - a->vm_start) >> PAGE_SHIFT);
}

/*
 * Do some basic sanity checking to see if we can re-use the anon_vma
 * from 'old'. The 'a'/'b' vma's are in VM order - one of them will be
 * the same as 'old', the other will be the new one that is trying
 * to share the anon_vma.
 *
 * NOTE! This runs with mm_sem held for reading, so it is possible that
 * the anon_vma of 'old' is concurrently in the process of being set up
 * by another page fault trying to merge _that_. But that's ok: if it
 * is being set up, that automatically means that it will be a singleton
 * acceptable for merging, so we can do all of this optimistically. But
 * we do that READ_ONCE() to make sure that we never re-load the pointer.
 *
 * IOW: that the "list_is_singular()" test on the anon_vma_chain only
 * matters for the 'stable anon_vma' case (ie the thing we want to avoid
 * is to return an anon_vma that is "complex" due to having gone through
 * a fork).
 *
 * We also make sure that the two vma's are compatible (adjacent,
 * and with the same memory policies). That's all stable, even with just
 * a read lock on the mm_sem.
 */
static struct anon_vma *
reusable_anon_vma(struct vm_area_struct *old,
                  struct vm_area_struct *a, struct vm_area_struct *b)
{
    if (anon_vma_compatible(a, b)) {
        struct anon_vma *anon_vma = READ_ONCE(old->anon_vma);

        if (anon_vma && list_is_singular(&old->anon_vma_chain))
            return anon_vma;
    }
    return NULL;
}

/*
 * find_mergeable_anon_vma is used by anon_vma_prepare, to check
 * neighbouring vmas for a suitable anon_vma, before it goes off
 * to allocate a new anon_vma.  It checks because a repetitive
 * sequence of mprotects and faults may otherwise lead to distinct
 * anon_vmas being allocated, preventing vma merge in subsequent
 * mprotect.
 */
struct anon_vma *find_mergeable_anon_vma(struct vm_area_struct *vma)
{
    struct anon_vma *anon_vma = NULL;

    /* Try next first. */
    if (vma->vm_next) {
        anon_vma = reusable_anon_vma(vma->vm_next, vma, vma->vm_next);
        if (anon_vma)
            return anon_vma;
    }

    /* Try prev next. */
    if (vma->vm_prev)
        anon_vma = reusable_anon_vma(vma->vm_prev, vma->vm_prev, vma);

    /*
     * We might reach here with anon_vma == NULL if we can't find
     * any reusable anon_vma.
     * There's no absolute need to look only at touching neighbours:
     * we could search further afield for "compatible" anon_vmas.
     * But it would probably just be a waste of time searching,
     * or lead to too many vmas hanging off the same anon_vma.
     * We're trying to allow mprotect remerging later on,
     * not trying to minimize memory used for anon_vmas.
     */
    return anon_vma;
}

/* Get an address range which is currently unmapped.
 * For shmat() with addr=0.
 *
 * Ugly calling convention alert:
 * Return value with the low bits set means error value,
 * ie
 *  if (ret & ~PAGE_MASK)
 *      error = ret;
 *
 * This function "knows" that -ENOMEM has the bits set.
 */
unsigned long
arch_get_unmapped_area(struct file *filp, unsigned long addr,
        unsigned long len, unsigned long pgoff, unsigned long flags)
{
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma, *prev;
    struct vm_unmapped_area_info info;
    const unsigned long mmap_end = arch_get_mmap_end(addr);

#if 0
    if (len > mmap_end - mmap_min_addr)
        return -ENOMEM;
#endif

    if (flags & MAP_FIXED)
        return addr;

    panic("%s: END!\n", __func__);
}

/*
 * munmap_vma_range() - munmap VMAs that overlap a range.
 * @mm: The mm struct
 * @start: The start of the range.
 * @len: The length of the range.
 * @pprev: pointer to the pointer that will be set to previous vm_area_struct
 * @rb_link: the rb_node
 * @rb_parent: the parent rb_node
 *
 * Find all the vm_area_struct that overlap from @start to
 * @end and munmap them.  Set @pprev to the previous vm_area_struct.
 *
 * Returns: -ENOMEM on munmap failure or 0 on success.
 */
static inline int
munmap_vma_range(struct mm_struct *mm, unsigned long start, unsigned long len,
                 struct vm_area_struct **pprev, struct rb_node ***link,
                 struct rb_node **parent, struct list_head *uf)
{

    while (find_vma_links(mm, start, start + len, pprev, link, parent))
        if (do_munmap(mm, start, len, uf))
            return -ENOMEM;

    return 0;
}

/*
 *  this is really a simplified "do_mmap".  it only handles
 *  anonymous maps.  eventually we may be able to do some
 *  brk-specific accounting here.
 */
static int do_brk_flags(unsigned long addr, unsigned long len,
                        unsigned long flags, struct list_head *uf)
{
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma, *prev;
    struct rb_node **rb_link, *rb_parent;
    pgoff_t pgoff = addr >> PAGE_SHIFT;
    int error;
    unsigned long mapped_addr;

    /* Until we need other flags, refuse anything except VM_EXEC. */
    if ((flags & (~VM_EXEC)) != 0)
        return -EINVAL;
    flags |= VM_DATA_DEFAULT_FLAGS | VM_ACCOUNT | mm->def_flags;

    mapped_addr = get_unmapped_area(NULL, addr, len, 0, MAP_FIXED);
    if (IS_ERR_VALUE(mapped_addr))
        return mapped_addr;

    error = mlock_future_check(mm, mm->def_flags, len);
    if (error)
        return error;

    /* Clear old maps, set up prev, rb_link, rb_parent, and uf */
    if (munmap_vma_range(mm, addr, len, &prev, &rb_link, &rb_parent, uf))
        return -ENOMEM;

    /* Check against address space limits *after* clearing old maps... */
    if (!may_expand_vm(mm, flags, len >> PAGE_SHIFT))
        return -ENOMEM;

    if (mm->map_count > sysctl_max_map_count)
        return -ENOMEM;

#if 0
    if (security_vm_enough_memory_mm(mm, len >> PAGE_SHIFT))
        return -ENOMEM;
#endif

    /* Can we just expand an old private anonymous mapping? */
    vma = vma_merge(mm, prev, addr, addr + len, flags,
                    NULL, NULL, pgoff, NULL, NULL_VM_UFFD_CTX, NULL);
    if (vma)
        goto out;

    /*
     * create a vma struct for an anonymous mapping
     */
    vma = vm_area_alloc(mm);
    if (!vma) {
        //vm_unacct_memory(len >> PAGE_SHIFT);
        return -ENOMEM;
    }

    vma_set_anonymous(vma);
    vma->vm_start = addr;
    vma->vm_end = addr + len;
    vma->vm_pgoff = pgoff;
    vma->vm_flags = flags;
    vma->vm_page_prot = vm_get_page_prot(flags);
    vma_link(mm, vma, prev, rb_link, rb_parent);
 out:
    //perf_event_mmap(vma);
    mm->total_vm += len >> PAGE_SHIFT;
    mm->data_vm += len >> PAGE_SHIFT;
    if (flags & VM_LOCKED)
        mm->locked_vm += (len >> PAGE_SHIFT);
    vma->vm_flags |= VM_SOFTDIRTY;
    return 0;
}

int vm_brk_flags(unsigned long addr, unsigned long request, unsigned long flags)
{
    struct mm_struct *mm = current->mm;
    unsigned long len;
    int ret;
    bool populate;
    LIST_HEAD(uf);

    len = PAGE_ALIGN(request);
    if (len < request)
        return -ENOMEM;
    if (!len)
        return 0;

    if (mmap_write_lock_killable(mm))
        return -EINTR;

    ret = do_brk_flags(addr, len, flags, &uf);
    populate = ((mm->def_flags & VM_LOCKED) != 0);
    mmap_write_unlock(mm);
    if (populate && !ret)
        mm_populate(addr, len);
    return ret;
}
EXPORT_SYMBOL(vm_brk_flags);

/*
 * If a hint addr is less than mmap_min_addr change hint to be as
 * low as possible but still greater than mmap_min_addr
 */
static inline unsigned long round_hint_to_min(unsigned long hint)
{
    hint &= PAGE_MASK;
    if (((void *)hint != NULL) &&
        (hint < mmap_min_addr))
        return PAGE_ALIGN(mmap_min_addr);
    return hint;
}

unsigned long
get_unmapped_area(struct file *file, unsigned long addr, unsigned long len,
                  unsigned long pgoff, unsigned long flags)
{
    unsigned long (*get_area)(struct file *, unsigned long,
                              unsigned long, unsigned long, unsigned long);

    /* Careful about overflows.. */
    if (len > TASK_SIZE)
        return -ENOMEM;

    get_area = current->mm->get_unmapped_area;
    if (file) {
        if (file->f_op->get_unmapped_area)
            get_area = file->f_op->get_unmapped_area;
    } else if (flags & MAP_SHARED) {
        /*
         * mmap_region() will call shmem_zero_setup() to create a file,
         * so use shmem's get_unmapped_area in case it can be huge.
         * do_mmap() will clear pgoff, so match alignment.
         */
        pgoff = 0;
        get_area = shmem_get_unmapped_area;
    }

    addr = get_area(file, addr, len, pgoff, flags);
    if (IS_ERR_VALUE(addr))
        return addr;

    if (addr > TASK_SIZE - len)
        return -ENOMEM;
    if (offset_in_page(addr))
        return -EINVAL;

    return addr;
}

int mlock_future_check(struct mm_struct *mm, unsigned long flags,
                       unsigned long len)
{
    unsigned long locked, lock_limit;

    /*  mlock MCL_FUTURE? */
    if (flags & VM_LOCKED) {
        locked = len >> PAGE_SHIFT;
        locked += mm->locked_vm;
        lock_limit = rlimit(RLIMIT_MEMLOCK);
        lock_limit >>= PAGE_SHIFT;
    }
    return 0;
}

static inline u64 file_mmap_size_max(struct file *file, struct inode *inode)
{
    if (S_ISREG(inode->i_mode))
        return MAX_LFS_FILESIZE;

    if (S_ISBLK(inode->i_mode))
        return MAX_LFS_FILESIZE;

    if (S_ISSOCK(inode->i_mode))
        return MAX_LFS_FILESIZE;

    /* Special "we do even unsigned file positions" case */
    if (file->f_mode & FMODE_UNSIGNED_OFFSET)
        return 0;

    /* Yes, random drivers might want more. But I'm tired of buggy drivers */
    return ULONG_MAX;
}

static inline bool file_mmap_ok(struct file *file, struct inode *inode,
                                unsigned long pgoff, unsigned long len)
{
    u64 maxsize = file_mmap_size_max(file, inode);

    if (maxsize && len > maxsize)
        return false;
    maxsize -= len;
    if (pgoff > maxsize >> PAGE_SHIFT)
        return false;
    return true;
}

/* Munmap is split into 2 main parts -- this part which finds
 * what needs doing, and the areas themselves, which do the
 * work.  This now handles partial unmappings.
 * Jeremy Fitzhardinge <jeremy@goop.org>
 */
int __do_munmap(struct mm_struct *mm, unsigned long start, size_t len,
                struct list_head *uf, bool downgrade)
{
    unsigned long end;
    struct vm_area_struct *vma, *prev, *last;

    if ((offset_in_page(start)) || start > TASK_SIZE || len > TASK_SIZE-start)
        return -EINVAL;

    len = PAGE_ALIGN(len);
    end = start + len;
    if (len == 0)
        return -EINVAL;

    panic("%s: END!\n", __func__);
}

int do_munmap(struct mm_struct *mm, unsigned long start, size_t len,
              struct list_head *uf)
{
    return __do_munmap(mm, start, len, uf, false);
}

static unsigned long
count_vma_pages_range(struct mm_struct *mm,
                      unsigned long addr, unsigned long end)
{
    unsigned long nr_pages = 0;
    struct vm_area_struct *vma;

    /* Find first overlapping mapping */
    vma = find_vma_intersection(mm, addr, end);
    if (!vma)
        return 0;

    nr_pages = (min(end, vma->vm_end) - max(addr, vma->vm_start)) >> PAGE_SHIFT;

    /* Iterate over the rest of the overlaps */
    for (vma = vma->vm_next; vma; vma = vma->vm_next) {
        unsigned long overlap_len;

        if (vma->vm_start > end)
            break;

        overlap_len = min(end, vma->vm_end) - vma->vm_start;
        nr_pages += overlap_len >> PAGE_SHIFT;
    }

    return nr_pages;
}

/*
 * We account for memory if it's a private writeable mapping,
 * not hugepages and VM_NORESERVE wasn't set.
 */
static inline int accountable_mapping(struct file *file, vm_flags_t vm_flags)
{
#if 0
    /*
     * hugetlb has its own accounting separate from the core VM
     * VM_HUGETLB may not be set yet so we cannot check for that flag.
     */
    if (file && is_file_hugepages(file))
        return 0;

    return (vm_flags & (VM_NORESERVE | VM_SHARED | VM_WRITE)) == VM_WRITE;
#endif
    panic("%s: END!\n", __func__);
}

/*
 * vma_next() - Get the next VMA.
 * @mm: The mm_struct.
 * @vma: The current vma.
 *
 * If @vma is NULL, return the first vma in the mm.
 *
 * Returns: The next VMA after @vma.
 */
static inline struct vm_area_struct *vma_next(struct mm_struct *mm,
                                              struct vm_area_struct *vma)
{
    if (!vma)
        return mm->mmap;

    return vma->vm_next;
}

/*
 * If the vma has a ->close operation then the driver probably needs to release
 * per-vma resources, so we don't attempt to merge those.
 */
static inline int is_mergeable_vma(struct vm_area_struct *vma,
                                   struct file *file, unsigned long vm_flags,
                                   struct vm_userfaultfd_ctx vm_userfaultfd_ctx,
                                   struct anon_vma_name *anon_name)
{
    /*
     * VM_SOFTDIRTY should not prevent from VMA merging, if we
     * match the flags but dirty bit -- the caller should mark
     * merged VMA as dirty. If dirty bit won't be excluded from
     * comparison, we increase pressure on the memory system forcing
     * the kernel to generate new VMAs when old one could be
     * extended instead.
     */
    if ((vma->vm_flags ^ vm_flags) & ~VM_SOFTDIRTY)
        return 0;
    if (vma->vm_file != file)
        return 0;
    if (vma->vm_ops && vma->vm_ops->close)
        return 0;
    return 1;
}

static inline int is_mergeable_anon_vma(struct anon_vma *anon_vma1,
                                        struct anon_vma *anon_vma2,
                                        struct vm_area_struct *vma)
{
    /*
     * The list_is_singular() test is to avoid merging VMA cloned from
     * parents. This can improve scalability caused by anon_vma lock.
     */
    if ((!anon_vma1 || !anon_vma2) &&
        (!vma || list_is_singular(&vma->anon_vma_chain)))
        return 1;
    return anon_vma1 == anon_vma2;
}

/*
 * Return true if we can merge this (vm_flags,anon_vma,file,vm_pgoff)
 * beyond (at a higher virtual address and file offset than) the vma.
 *
 * We cannot merge two vmas if they have differently assigned (non-NULL)
 * anon_vmas, nor if same anon_vma is assigned but offsets incompatible.
 */
static int
can_vma_merge_after(struct vm_area_struct *vma, unsigned long vm_flags,
                    struct anon_vma *anon_vma, struct file *file,
                    pgoff_t vm_pgoff,
                    struct vm_userfaultfd_ctx vm_userfaultfd_ctx,
                    struct anon_vma_name *anon_name)
{
    if (is_mergeable_vma(vma, file, vm_flags, vm_userfaultfd_ctx, anon_name) &&
        is_mergeable_anon_vma(anon_vma, vma->anon_vma, vma)) {
        pgoff_t vm_pglen;
        vm_pglen = vma_pages(vma);
        if (vma->vm_pgoff + vm_pglen == vm_pgoff)
            return 1;
    }
    return 0;
}

/*
 * Return true if we can merge this (vm_flags,anon_vma,file,vm_pgoff)
 * in front of (at a lower virtual address and file offset than) the vma.
 *
 * We cannot merge two vmas if they have differently assigned (non-NULL)
 * anon_vmas, nor if same anon_vma is assigned but offsets incompatible.
 *
 * We don't check here for the merged mmap wrapping around the end of pagecache
 * indices (16TB on ia32) because do_mmap() does not permit mmap's which
 * wrap, nor mmaps which cover the final page at index -1UL.
 */
static int
can_vma_merge_before(struct vm_area_struct *vma, unsigned long vm_flags,
                     struct anon_vma *anon_vma, struct file *file,
                     pgoff_t vm_pgoff,
                     struct vm_userfaultfd_ctx vm_userfaultfd_ctx,
                     struct anon_vma_name *anon_name)
{
    if (is_mergeable_vma(vma, file, vm_flags, vm_userfaultfd_ctx, anon_name) &&
        is_mergeable_anon_vma(anon_vma, vma->anon_vma, vma)) {
        if (vma->vm_pgoff == vm_pgoff)
            return 1;
    }
    return 0;
}

/*
 * Helper for vma_adjust() in the split_vma insert case: insert a vma into the
 * mm's list and rbtree.  It has already been inserted into the interval tree.
 */
static void __insert_vm_struct(struct mm_struct *mm, struct vm_area_struct *vma)
{
    struct vm_area_struct *prev;
    struct rb_node **rb_link, *rb_parent;

    if (find_vma_links(mm, vma->vm_start, vma->vm_end,
                       &prev, &rb_link, &rb_parent))
        BUG();

    __vma_link(mm, vma, prev, rb_link, rb_parent);
    mm->map_count++;
}

static void __vma_rb_erase(struct vm_area_struct *vma, struct rb_root *root)
{
    /*
     * Note rb_erase_augmented is a fairly large inline function,
     * so make sure we instantiate it only once with our desired
     * augmented rbtree callbacks.
     */
    rb_erase_augmented(&vma->vm_rb, root, &vma_gap_callbacks);
}

static __always_inline
void vma_rb_erase_ignore(struct vm_area_struct *vma,
                         struct rb_root *root,
                         struct vm_area_struct *ignore)
{
    /*
     * All rb_subtree_gap values must be consistent prior to erase,
     * with the possible exception of
     *
     * a. the "next" vma being erased if next->vm_start was reduced in
     *    __vma_adjust() -> __vma_unlink()
     * b. the vma being erased in detach_vmas_to_be_unmapped() ->
     *    vma_rb_erase()
     */
    validate_mm_rb(root, ignore);

    __vma_rb_erase(vma, root);
}

static __always_inline
void __vma_unlink(struct mm_struct *mm,
                  struct vm_area_struct *vma,
                  struct vm_area_struct *ignore)
{
    vma_rb_erase_ignore(vma, &mm->mm_rb, ignore);
    __vma_unlink_list(mm, vma);
    /* Kill the cache */
    vmacache_invalidate(mm);
}

/*
 * Requires inode->i_mapping->i_mmap_rwsem
 */
static void __remove_shared_vm_struct(struct vm_area_struct *vma,
                                      struct file *file,
                                      struct address_space *mapping)
{
    if (vma->vm_flags & VM_SHARED)
        mapping_unmap_writable(mapping);

    flush_dcache_mmap_lock(mapping);
    vma_interval_tree_remove(vma, &mapping->i_mmap);
    flush_dcache_mmap_unlock(mapping);
}

/*
 * We cannot adjust vm_start, vm_end, vm_pgoff fields of a vma that
 * is already present in an i_mmap tree without adjusting the tree.
 * The following helper function should be used when such adjustments
 * are necessary.  The "insert" vma (if any) is to be inserted
 * before we drop the necessary locks.
 */
int __vma_adjust(struct vm_area_struct *vma, unsigned long start,
                 unsigned long end, pgoff_t pgoff,
                 struct vm_area_struct *insert,
                 struct vm_area_struct *expand)
{
    struct mm_struct *mm = vma->vm_mm;
    struct vm_area_struct *next = vma->vm_next, *orig_vma = vma;
    struct address_space *mapping = NULL;
    struct rb_root_cached *root = NULL;
    struct anon_vma *anon_vma = NULL;
    struct file *file = vma->vm_file;
    bool start_changed = false, end_changed = false;
    long adjust_next = 0;
    int remove_next = 0;

    if (next && !insert) {
        struct vm_area_struct *exporter = NULL, *importer = NULL;

        if (end >= next->vm_end) {
            panic("%s: 1.1!\n", __func__);
        } else if (end > next->vm_start) {
            panic("%s: 1.2!\n", __func__);
        } else if (end < vma->vm_end) {
            panic("%s: 1.3!\n", __func__);
        }

        /*
         * Easily overlooked: when mprotect shifts the boundary,
         * make sure the expanding vma has anon_vma set if the
         * shrinking vma had, to cover any anon pages imported.
         */
        if (exporter && exporter->anon_vma && !importer->anon_vma) {
            int error;

            importer->anon_vma = exporter->anon_vma;
            error = anon_vma_clone(importer, exporter);
            if (error)
                return error;
        }
    }

 again:
    if (file) {
#if 0
        mapping = file->f_mapping;
        root = &mapping->i_mmap;
        uprobe_munmap(vma, vma->vm_start, vma->vm_end);

        if (adjust_next)
            uprobe_munmap(next, next->vm_start, next->vm_end);

        i_mmap_lock_write(mapping);
        if (insert) {
            /*
             * Put into interval tree now, so instantiated pages
             * are visible to arm/parisc __flush_dcache_page
             * throughout; but we cannot insert into address
             * space until vma start or end is updated.
             */
            __vma_link_file(insert);
        }
#endif

        panic("%s: file 1 !\n", __func__);
    }

    anon_vma = vma->anon_vma;
    if (!anon_vma && adjust_next)
        anon_vma = next->anon_vma;
    if (anon_vma) {
        VM_WARN_ON(adjust_next && next->anon_vma && anon_vma != next->anon_vma);
        anon_vma_lock_write(anon_vma);
        anon_vma_interval_tree_pre_update_vma(vma);
        if (adjust_next)
            anon_vma_interval_tree_pre_update_vma(next);
    }

    if (file) {
        flush_dcache_mmap_lock(mapping);
        vma_interval_tree_remove(vma, root);
        if (adjust_next)
            vma_interval_tree_remove(next, root);
    }

    if (start != vma->vm_start) {
        vma->vm_start = start;
        start_changed = true;
    }
    if (end != vma->vm_end) {
        vma->vm_end = end;
        end_changed = true;
    }
    vma->vm_pgoff = pgoff;
    if (adjust_next) {
        next->vm_start += adjust_next;
        next->vm_pgoff += adjust_next >> PAGE_SHIFT;
    }

    if (file) {
        if (adjust_next)
            vma_interval_tree_insert(next, root);
        vma_interval_tree_insert(vma, root);
        flush_dcache_mmap_unlock(mapping);
    }

    if (remove_next) {
        /*
         * vma_merge has merged next into vma, and needs
         * us to remove next before dropping the locks.
         */
        if (remove_next != 3)
            __vma_unlink(mm, next, next);
        else
            /*
             * vma is not before next if they've been
             * swapped.
             *
             * pre-swap() next->vm_start was reduced so
             * tell validate_mm_rb to ignore pre-swap()
             * "next" (which is stored in post-swap()
             * "vma").
             */
            __vma_unlink(mm, next, vma);
        if (file)
            __remove_shared_vm_struct(next, file, mapping);
    } else if (insert) {
        /*
         * split_vma has split insert from vma, and needs
         * us to insert it before dropping the locks
         * (it may either follow vma or precede it).
         */
        __insert_vm_struct(mm, insert);
    } else {
        if (start_changed)
            vma_gap_update(vma);
        if (end_changed) {
            if (!next)
                mm->highest_vm_end = vm_end_gap(vma);
            else if (!adjust_next)
                vma_gap_update(next);
        }
    }

    if (anon_vma) {
        anon_vma_interval_tree_post_update_vma(vma);
        if (adjust_next)
            anon_vma_interval_tree_post_update_vma(next);
        anon_vma_unlock_write(anon_vma);
    }

    if (file) {
        i_mmap_unlock_write(mapping);
    }

    if (remove_next) {
        if (file) {
            fput(file);
        }
        if (next->anon_vma)
            anon_vma_merge(vma, next);
        mm->map_count--;
        vm_area_free(next);
        /*
         * In mprotect's case 6 (see comments on vma_merge),
         * we must remove another next too. It would clutter
         * up the code too much to do both in one go.
         */
        if (remove_next != 3) {
            /*
             * If "next" was removed and vma->vm_end was
             * expanded (up) over it, in turn
             * "next->vm_prev->vm_end" changed and the
             * "vma->vm_next" gap must be updated.
             */
            next = vma->vm_next;
        } else {
            /*
             * For the scope of the comment "next" and
             * "vma" considered pre-swap(): if "vma" was
             * removed, next->vm_start was expanded (down)
             * over it and the "next" gap must be updated.
             * Because of the swap() the post-swap() "vma"
             * actually points to pre-swap() "next"
             * (post-swap() "next" as opposed is now a
             * dangling pointer).
             */
            next = vma;
        }
        if (remove_next == 2) {
            remove_next = 1;
            end = next->vm_end;
            goto again;
        }
        else if (next)
            vma_gap_update(next);
        else {
            /*
             * If remove_next == 2 we obviously can't
             * reach this path.
             *
             * If remove_next == 3 we can't reach this
             * path because pre-swap() next is always not
             * NULL. pre-swap() "next" is not being
             * removed and its next->vm_end is not altered
             * (and furthermore "end" already matches
             * next->vm_end in remove_next == 3).
             *
             * We reach this only in the remove_next == 1
             * case if the "next" vma that was removed was
             * the highest vma of the mm. However in such
             * case next->vm_end == "end" and the extended
             * "vma" has vma->vm_end == next->vm_end so
             * mm->highest_vm_end doesn't need any update
             * in remove_next == 1 case.
             */
            VM_WARN_ON(mm->highest_vm_end != vm_end_gap(vma));
        }
    }

    validate_mm(mm);

    return 0;
}

/*
 * Given a mapping request (addr,end,vm_flags,file,pgoff,anon_name),
 * figure out whether that can be merged with its predecessor or its
 * successor.  Or both (it neatly fills a hole).
 *
 * In most cases - when called for mmap, brk or mremap - [addr,end) is
 * certain not to be mapped by the time vma_merge is called; but when
 * called for mprotect, it is certain to be already mapped (either at
 * an offset within prev, or at the start of next), and the flags of
 * this area are about to be changed to vm_flags - and the no-change
 * case has already been eliminated.
 *
 * The following mprotect cases have to be considered, where AAAA is
 * the area passed down from mprotect_fixup, never extending beyond one
 * vma, PPPPPP is the prev vma specified, and NNNNNN the next vma after:
 *
 *     AAAA             AAAA                   AAAA
 *    PPPPPPNNNNNN    PPPPPPNNNNNN       PPPPPPNNNNNN
 *    cannot merge    might become       might become
 *                    PPNNNNNNNNNN       PPPPPPPPPPNN
 *    mmap, brk or    case 4 below       case 5 below
 *    mremap move:
 *                        AAAA               AAAA
 *                    PPPP    NNNN       PPPPNNNNXXXX
 *                    might become       might become
 *                    PPPPPPPPPPPP 1 or  PPPPPPPPPPPP 6 or
 *                    PPPPPPPPNNNN 2 or  PPPPPPPPXXXX 7 or
 *                    PPPPNNNNNNNN 3     PPPPXXXXXXXX 8
 *
 * It is important for case 8 that the vma NNNN overlapping the
 * region AAAA is never going to extended over XXXX. Instead XXXX must
 * be extended in region AAAA and NNNN must be removed. This way in
 * all cases where vma_merge succeeds, the moment vma_adjust drops the
 * rmap_locks, the properties of the merged vma will be already
 * correct for the whole merged range. Some of those properties like
 * vm_page_prot/vm_flags may be accessed by rmap_walks and they must
 * be correct for the whole merged range immediately after the
 * rmap_locks are released. Otherwise if XXXX would be removed and
 * NNNN would be extended over the XXXX range, remove_migration_ptes
 * or other rmap walkers (if working on addresses beyond the "end"
 * parameter) may establish ptes with the wrong permissions of NNNN
 * instead of the right permissions of XXXX.
 */
struct vm_area_struct *
vma_merge(struct mm_struct *mm,
          struct vm_area_struct *prev, unsigned long addr,
          unsigned long end, unsigned long vm_flags,
          struct anon_vma *anon_vma, struct file *file,
          pgoff_t pgoff, struct mempolicy *policy,
          struct vm_userfaultfd_ctx vm_userfaultfd_ctx,
          struct anon_vma_name *anon_name)
{
    pgoff_t pglen = (end - addr) >> PAGE_SHIFT;
    struct vm_area_struct *area, *next;
    int err;

    /*
     * We later require that vma->vm_flags == vm_flags,
     * so this tests vma->vm_flags & VM_SPECIAL, too.
     */
    if (vm_flags & VM_SPECIAL)
        return NULL;

    next = vma_next(mm, prev);
    area = next;
    if (area && area->vm_end == end)        /* cases 6, 7, 8 */
        next = next->vm_next;

    /* verify some invariant that must be enforced by the caller */
    VM_WARN_ON(prev && addr <= prev->vm_start);
    VM_WARN_ON(area && end > area->vm_end);
    VM_WARN_ON(addr >= end);

    /*
     * Can it merge with the predecessor?
     */
    if (prev && prev->vm_end == addr &&
        can_vma_merge_after(prev, vm_flags, anon_vma, file, pgoff,
                            vm_userfaultfd_ctx, anon_name)) {
        /*
         * OK, it can.  Can we now merge in the successor as well?
         */
        if (next && end == next->vm_start &&
            can_vma_merge_before(next, vm_flags, anon_vma, file, pgoff+pglen,
                                 vm_userfaultfd_ctx, anon_name) &&
            is_mergeable_anon_vma(prev->anon_vma, next->anon_vma, NULL)) {
            /* cases 1, 6 */
            err = __vma_adjust(prev, prev->vm_start,
                               next->vm_end, prev->vm_pgoff, NULL,
                               prev);
        } else  /* cases 2, 5, 7 */
            err = __vma_adjust(prev, prev->vm_start,
                               end, prev->vm_pgoff, NULL, prev);
        if (err)
            return NULL;
        return prev;
    }

    /*
     * Can this new request be merged in front of next?
     */
    if (next && end == next->vm_start &&
        can_vma_merge_before(next, vm_flags, anon_vma, file, pgoff+pglen,
                             vm_userfaultfd_ctx, anon_name)) {
        panic("%s: front!\n", __func__);
    }

    return NULL;
}

static pgprot_t vm_pgprot_modify(pgprot_t oldprot, unsigned long vm_flags)
{
    return pgprot_modify(oldprot, vm_get_page_prot(vm_flags));
}

/*
 * Some shared mappings will want the pages marked read-only
 * to track write events. If so, we'll downgrade vm_page_prot
 * to the private version (using protection_map[] without the
 * VM_SHARED bit).
 */
int vma_wants_writenotify(struct vm_area_struct *vma, pgprot_t vm_page_prot)
{
    vm_flags_t vm_flags = vma->vm_flags;
    const struct vm_operations_struct *vm_ops = vma->vm_ops;

    /* If it was private or non-writable, the write bit is already clear */
    if ((vm_flags & (VM_WRITE|VM_SHARED)) != ((VM_WRITE|VM_SHARED)))
        return 0;

    panic("%s: END!\n", __func__);
}

/* Update vma->vm_page_prot to reflect vma->vm_flags. */
void vma_set_page_prot(struct vm_area_struct *vma)
{
    unsigned long vm_flags = vma->vm_flags;
    pgprot_t vm_page_prot;

    vm_page_prot = vm_pgprot_modify(vma->vm_page_prot, vm_flags);
    if (vma_wants_writenotify(vma, vm_page_prot)) {
        vm_flags &= ~VM_SHARED;
        vm_page_prot = vm_pgprot_modify(vm_page_prot, vm_flags);
    }
    /* remove_protection_ptes reads vma->vm_page_prot without mmap_lock */
    WRITE_ONCE(vma->vm_page_prot, vm_page_prot);
}

/*
 * Get rid of page table information in the indicated region.
 *
 * Called with the mm semaphore held.
 */
static void unmap_region(struct mm_struct *mm,
                         struct vm_area_struct *vma,
                         struct vm_area_struct *prev,
                         unsigned long start, unsigned long end)
{
#if 0
    struct vm_area_struct *next = vma_next(mm, prev);
    struct mmu_gather tlb;

    lru_add_drain();
    tlb_gather_mmu(&tlb, mm);
    update_hiwater_rss(mm);
    unmap_vmas(&tlb, vma, start, end);
    free_pgtables(&tlb, vma, prev ? prev->vm_end : FIRST_USER_ADDRESS,
                 next ? next->vm_start : USER_PGTABLES_CEILING);
    tlb_finish_mmu(&tlb);
#endif
    panic("%s: END!\n", __func__);
}

unsigned long mmap_region(struct file *file, unsigned long addr,
                          unsigned long len, vm_flags_t vm_flags,
                          unsigned long pgoff,
                          struct list_head *uf)
{
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *vma, *prev, *merge;
    int error;
    struct rb_node **rb_link, *rb_parent;
    unsigned long charged = 0;

    /* Check against address space limit. */
    if (!may_expand_vm(mm, vm_flags, len >> PAGE_SHIFT)) {
        unsigned long nr_pages;

        /*
         * MAP_FIXED may remove pages of mappings that intersects with
         * requested mapping. Account for the pages it would unmap.
         */
        nr_pages = count_vma_pages_range(mm, addr, addr + len);

        if (!may_expand_vm(mm, vm_flags, (len >> PAGE_SHIFT) - nr_pages))
            return -ENOMEM;
    }

    /* Clear old maps, set up prev, rb_link, rb_parent, and uf */
    if (munmap_vma_range(mm, addr, len, &prev, &rb_link, &rb_parent, uf))
        return -ENOMEM;
    /*
     * Private writable mapping: check memory availability
     */
#if 0
    if (accountable_mapping(file, vm_flags)) {
        charged = len >> PAGE_SHIFT;
        vm_flags |= VM_ACCOUNT;
    }
#endif

    /*
     * Can we just expand an old mapping?
     */
    vma = vma_merge(mm, prev, addr, addr + len, vm_flags,
                    NULL, file, pgoff, NULL, NULL_VM_UFFD_CTX, NULL);
    if (vma)
        goto out;

    /*
     * Determine the object being mapped and call the appropriate
     * specific mapper. the address has already been validated, but
     * not unmapped, but the maps are removed from the list.
     */
    vma = vm_area_alloc(mm);
    if (!vma) {
        error = -ENOMEM;
        goto unacct_error;
    }

    vma->vm_start = addr;
    vma->vm_end = addr + len;
    vma->vm_flags = vm_flags;
    vma->vm_page_prot = vm_get_page_prot(vm_flags);
    vma->vm_pgoff = pgoff;

    if (file) {
        if (vm_flags & VM_SHARED) {
            error = mapping_map_writable(file->f_mapping);
            if (error)
                goto free_vma;
        }

        vma->vm_file = get_file(file);
        error = call_mmap(file, vma);
        if (error)
            goto unmap_and_free_vma;

        /* Can addr have changed??
         *
         * Answer: Yes, several device drivers can do it in their
         *         f_op->mmap method. -DaveM
         * Bug: If addr is changed, prev, rb_link, rb_parent should
         *      be updated for vma_link()
         */
        WARN_ON_ONCE(addr != vma->vm_start);

        addr = vma->vm_start;

        /* If vm_flags changed after call_mmap(), we should try merge vma again
         * as we may succeed this time.
         */
        if (unlikely(vm_flags != vma->vm_flags && prev)) {
            panic("%s: file 1!\n", __func__);
        }

        vm_flags = vma->vm_flags;
    } else if (vm_flags & VM_SHARED) {
#if 0
        error = shmem_zero_setup(vma);
        if (error)
            goto free_vma;
#endif
        panic("%s: VM_SHARED!\n", __func__);
    } else {
        vma_set_anonymous(vma);
    }

    vma_link(mm, vma, prev, rb_link, rb_parent);
    /* Once vma denies write, undo our temporary denial count */
 unmap_writable:
    if (file && vm_flags & VM_SHARED)
        mapping_unmap_writable(file->f_mapping);
    file = vma->vm_file;
 out:
    //perf_event_mmap(vma);

    vm_stat_account(mm, vm_flags, len >> PAGE_SHIFT);
    if (vm_flags & VM_LOCKED) {
        if ((vm_flags & VM_SPECIAL) || vma_is_dax(vma) ||
            is_vm_hugetlb_page(vma) || vma == get_gate_vma(current->mm))
            vma->vm_flags &= VM_LOCKED_CLEAR_MASK;
        else
            mm->locked_vm += (len >> PAGE_SHIFT);
    }

    /*
     * New (or expanded) vma always get soft dirty status.
     * Otherwise user-space soft-dirty page tracker won't
     * be able to distinguish situation when vma area unmapped,
     * then new mapped in-place (which must be aimed as
     * a completely new data area).
     */
    vma->vm_flags |= VM_SOFTDIRTY;

    vma_set_page_prot(vma);

    return addr;

 unmap_and_free_vma:
    fput(vma->vm_file);
    vma->vm_file = NULL;

    /* Undo any partial mapping done by a device driver. */
    unmap_region(mm, vma, prev, vma->vm_start, vma->vm_end);
    charged = 0;
    if (vm_flags & VM_SHARED)
        mapping_unmap_writable(file->f_mapping);
 free_vma:
    vm_area_free(vma);
 unacct_error:
#if 0
    if (charged)
        vm_unacct_memory(charged);
#endif
    return error;
}

/*
 * The caller must write-lock current->mm->mmap_lock.
 */
unsigned long do_mmap(struct file *file, unsigned long addr,
                      unsigned long len, unsigned long prot,
                      unsigned long flags, unsigned long pgoff,
                      unsigned long *populate, struct list_head *uf)
{
    struct mm_struct *mm = current->mm;
    vm_flags_t vm_flags;
    int pkey = 0;

    *populate = 0;

    if (!len)
        return -EINVAL;

    /*
     * Does the application expect PROT_READ to imply PROT_EXEC?
     *
     * (the exception is when the underlying filesystem is noexec
     *  mounted, in which case we dont add PROT_EXEC.)
     */
    if ((prot & PROT_READ) && (current->personality & READ_IMPLIES_EXEC))
        if (!(file && path_noexec(&file->f_path)))
            prot |= PROT_EXEC;

    /* force arch specific MAP_FIXED handling in get_unmapped_area */
    if (flags & MAP_FIXED_NOREPLACE)
        flags |= MAP_FIXED;

    if (!(flags & MAP_FIXED))
        addr = round_hint_to_min(addr);

    /* Careful about overflows.. */
    len = PAGE_ALIGN(len);
    if (!len)
        return -ENOMEM;

    /* offset overflow? */
    if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
        return -EOVERFLOW;

    /* Too many mappings? */
    if (mm->map_count > sysctl_max_map_count)
        return -ENOMEM;

    /* Obtain the address to map to. we verify (or select) it and ensure
     * that it represents a valid section of the address space.
     */
    addr = get_unmapped_area(file, addr, len, pgoff, flags);
    if (IS_ERR_VALUE(addr))
        return addr;

    if (flags & MAP_FIXED_NOREPLACE) {
        if (find_vma_intersection(mm, addr, addr + len))
            return -EEXIST;
    }

    /* Do simple checking here so the lower-level routines won't have
     * to. we assume access permissions have been handled by the open
     * of the memory object, so we don't do any here.
     */
    vm_flags = calc_vm_prot_bits(prot, pkey) | calc_vm_flag_bits(flags) |
        mm->def_flags | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

    if (flags & MAP_LOCKED)
        if (!can_do_mlock())
            return -EPERM;

    if (mlock_future_check(mm, vm_flags, len))
        return -EAGAIN;

    if (file) {
        struct inode *inode = file_inode(file);
        unsigned long flags_mask;

        if (!file_mmap_ok(file, inode, pgoff, len))
            return -EOVERFLOW;

        flags_mask = LEGACY_MAP_MASK | file->f_op->mmap_supported_flags;

        switch (flags & MAP_TYPE) {
        case MAP_SHARED:
            /*
             * Force use of MAP_SHARED_VALIDATE with non-legacy
             * flags. E.g. MAP_SYNC is dangerous to use with
             * MAP_SHARED as you don't know which consistency model
             * you will get. We silently ignore unsupported flags
             * with MAP_SHARED to preserve backward compatibility.
             */
            flags &= LEGACY_MAP_MASK;
            fallthrough;
        case MAP_SHARED_VALIDATE:
            if (flags & ~flags_mask)
                return -EOPNOTSUPP;
            if (prot & PROT_WRITE) {
                if (!(file->f_mode & FMODE_WRITE))
                    return -EACCES;
                if (IS_SWAPFILE(file->f_mapping->host))
                    return -ETXTBSY;
            }

            /*
             * Make sure we don't allow writing to an append-only
             * file..
             */
            if (IS_APPEND(inode) && (file->f_mode & FMODE_WRITE))
                return -EACCES;

            vm_flags |= VM_SHARED | VM_MAYSHARE;
            if (!(file->f_mode & FMODE_WRITE))
                vm_flags &= ~(VM_MAYWRITE | VM_SHARED);
            fallthrough;
        case MAP_PRIVATE:
            if (!(file->f_mode & FMODE_READ))
                return -EACCES;
            if (path_noexec(&file->f_path)) {
                if (vm_flags & VM_EXEC)
                    return -EPERM;
                vm_flags &= ~VM_MAYEXEC;
            }

            if (!file->f_op->mmap)
                return -ENODEV;
            if (vm_flags & (VM_GROWSDOWN|VM_GROWSUP))
                return -EINVAL;
            break;

        default:
            return -EINVAL;
        }
    } else {
        panic("%s: NOT file!\n", __func__);
    }

    /*
     * Set 'VM_NORESERVE' if we should not account for the
     * memory use of this mapping.
     */
    if (flags & MAP_NORESERVE) {
#if 0
        /* We honor MAP_NORESERVE if allowed to overcommit */
        if (sysctl_overcommit_memory != OVERCOMMIT_NEVER)
            vm_flags |= VM_NORESERVE;

        /* hugetlb applies strict overcommit unless MAP_NORESERVE */
        if (file && is_file_hugepages(file))
            vm_flags |= VM_NORESERVE;
#endif
        panic("%s: flags & MAP_NORESERVE!\n", __func__);
    }

    addr = mmap_region(file, addr, len, vm_flags, pgoff, uf);
    if (!IS_ERR_VALUE(addr) &&
        ((vm_flags & VM_LOCKED) ||
         (flags & (MAP_POPULATE | MAP_NONBLOCK)) == MAP_POPULATE))
        *populate = len;
    return addr;
}

SYSCALL_DEFINE1(brk, unsigned long, brk)
{
    unsigned long newbrk, oldbrk, origbrk;
    struct mm_struct *mm = current->mm;
    struct vm_area_struct *next;
    unsigned long min_brk;
    bool populate;
    bool downgraded = false;
    LIST_HEAD(uf);

    if (mmap_write_lock_killable(mm))
        return -EINTR;

    origbrk = mm->brk;

    /*
     * CONFIG_COMPAT_BRK can still be overridden by setting
     * randomize_va_space to 2, which will still cause mm->start_brk
     * to be arbitrarily shifted
     */
#if 0
    if (current->brk_randomized)
        min_brk = mm->start_brk;
    else
        min_brk = mm->end_data;
#else
    min_brk = mm->end_data;
#endif

    if (brk < min_brk)
        goto out;

    /*
     * Check against rlimit here. If this check is done later after the test
     * of oldbrk with newbrk then it can escape the test and let the data
     * segment grow beyond its set limit the in case where the limit is
     * not page aligned -Ram Gupta
     */
    if (check_data_rlimit(rlimit(RLIMIT_DATA), brk, mm->start_brk,
                          mm->end_data, mm->start_data))
        goto out;

    newbrk = PAGE_ALIGN(brk);
    oldbrk = PAGE_ALIGN(mm->brk);
    if (oldbrk == newbrk) {
        mm->brk = brk;
        goto success;
    }

    /*
     * Always allow shrinking brk.
     * __do_munmap() may downgrade mmap_lock to read.
     */
    if (brk <= mm->brk) {
        int ret;

        /*
         * mm->brk must to be protected by write mmap_lock so update it
         * before downgrading mmap_lock. When __do_munmap() fails,
         * mm->brk will be restored from origbrk.
         */
        mm->brk = brk;
        ret = __do_munmap(mm, newbrk, oldbrk-newbrk, &uf, true);
        if (ret < 0) {
            mm->brk = origbrk;
            goto out;
        } else if (ret == 1) {
            downgraded = true;
        }
        goto success;
    }

    /* Check against existing mmap mappings. */
    next = find_vma(mm, oldbrk);
    if (next && newbrk + PAGE_SIZE > vm_start_gap(next))
        goto out;

    /* Ok, looks good - let it rip. */
    if (do_brk_flags(oldbrk, newbrk-oldbrk, 0, &uf) < 0)
        goto out;
    mm->brk = brk;

 success:
    populate = newbrk > oldbrk && (mm->def_flags & VM_LOCKED) != 0;
    if (downgraded)
        mmap_read_unlock(mm);
    else
        mmap_write_unlock(mm);
    if (populate)
        mm_populate(oldbrk, newbrk - oldbrk);
    return brk;

 out:
    mmap_write_unlock(mm);
    return origbrk;
}

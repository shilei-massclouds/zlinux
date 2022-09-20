// SPDX-License-Identifier: GPL-2.0-only
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/compiler.h>
#include <linux/export.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/security.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#if 0
#include <linux/mman.h>
#include <linux/hugetlb.h>
#include <linux/userfaultfd_k.h>
#endif
#include <linux/vmalloc.h>
#include <linux/elf.h>
#include <linux/elf-randomize.h>
#include <linux/random.h>
#if 0
#include <linux/processor.h>
#endif
#include <linux/personality.h>
#include <linux/sizes.h>
#include <linux/compat.h>

#include <linux/uaccess.h>
#include <asm/sections.h>

#include "internal.h"

/*
 * Make sure vm_committed_as in one cacheline and not cacheline shared with
 * other variables. It can be updated by several CPUs frequently.
 */
struct percpu_counter vm_committed_as ____cacheline_aligned_in_smp;

int sysctl_max_map_count __read_mostly = DEFAULT_MAX_MAP_COUNT;

/**
 * kfree_const - conditionally free memory
 * @x: pointer to the memory
 *
 * Function calls kfree only if @x is not in .rodata section.
 */
void kfree_const(const void *x)
{
    if (!is_kernel_rodata((unsigned long)x))
        kfree(x);
}
EXPORT_SYMBOL(kfree_const);

/**
 * kstrdup - allocate space for and copy an existing string
 * @s: the string to duplicate
 * @gfp: the GFP mask used in the kmalloc() call when allocating memory
 *
 * Return: newly allocated copy of @s or %NULL in case of error
 */
char *kstrdup(const char *s, gfp_t gfp)
{
    size_t len;
    char *buf;

    if (!s)
        return NULL;

    len = strlen(s) + 1;
    buf = kmalloc_track_caller(len, gfp);
    if (buf)
        memcpy(buf, s, len);
    return buf;
}
EXPORT_SYMBOL(kstrdup);

/**
 * kstrdup_const - conditionally duplicate an existing const string
 * @s: the string to duplicate
 * @gfp: the GFP mask used in the kmalloc() call when allocating memory
 *
 * Note: Strings allocated by kstrdup_const should be freed by kfree_const and
 * must not be passed to krealloc().
 *
 * Return: source string if it is in .rodata section otherwise
 * fallback to kstrdup.
 */
const char *kstrdup_const(const char *s, gfp_t gfp)
{
    if (is_kernel_rodata((unsigned long)s))
        return s;

    return kstrdup(s, gfp);
}
EXPORT_SYMBOL(kstrdup_const);

/**
 * kvfree() - Free memory.
 * @addr: Pointer to allocated memory.
 *
 * kvfree frees memory allocated by any of vmalloc(), kmalloc() or kvmalloc().
 * It is slightly more efficient to use kfree() or vfree() if you are certain
 * that you know which one to use.
 *
 * Context: Either preemptible task context or not-NMI interrupt.
 */
void kvfree(const void *addr)
{
    if (is_vmalloc_addr(addr))
        vfree(addr);
    else
        kfree(addr);
}
EXPORT_SYMBOL(kvfree);

/**
 * kvmalloc_node - attempt to allocate physically contiguous memory, but upon
 * failure, fall back to non-contiguous (vmalloc) allocation.
 * @size: size of the request.
 * @flags: gfp mask for the allocation - must be compatible (superset) with GFP_KERNEL.
 * @node: numa node to allocate from
 *
 * Uses kmalloc to get the memory but if the allocation fails then falls back
 * to the vmalloc allocator. Use kvfree for freeing the memory.
 *
 * GFP_NOWAIT and GFP_ATOMIC are not supported, neither is the __GFP_NORETRY modifier.
 * __GFP_RETRY_MAYFAIL is supported, and it should be used only if kmalloc is
 * preferable to the vmalloc fallback, due to visible performance drawbacks.
 *
 * Return: pointer to the allocated memory of %NULL in case of failure
 */
void *kvmalloc_node(size_t size, gfp_t flags, int node)
{
    gfp_t kmalloc_flags = flags;
    void *ret;

    /*
     * We want to attempt a large physically contiguous block first because
     * it is less likely to fragment multiple larger blocks and therefore
     * contribute to a long term fragmentation less than vmalloc fallback.
     * However make sure that larger requests are not too disruptive - no
     * OOM killer and no allocation failure warnings as we have a fallback.
     */
    if (size > PAGE_SIZE) {
        kmalloc_flags |= __GFP_NOWARN;

        if (!(kmalloc_flags & __GFP_RETRY_MAYFAIL))
            kmalloc_flags |= __GFP_NORETRY;

        /* nofail semantic is implemented by the vmalloc fallback */
        kmalloc_flags &= ~__GFP_NOFAIL;
    }

    ret = kmalloc_node(size, kmalloc_flags, node);

    /*
     * It doesn't really make sense to fallback to vmalloc for sub page
     * requests
     */
    if (ret || size <= PAGE_SIZE)
        return ret;

    /* Don't even allow crazy sizes */
    if (unlikely(size > INT_MAX)) {
        WARN_ON_ONCE(!(flags & __GFP_NOWARN));
        return NULL;
    }

    /*
     * kvmalloc() can always use VM_ALLOW_HUGE_VMAP,
     * since the callers already cannot assume anything
     * about the resulting pointer, and cannot play
     * protection games.
     */
    return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
                                flags, PAGE_KERNEL, VM_ALLOW_HUGE_VMAP,
                                node, __builtin_return_address(0));
}

/**
 * kmemdup_nul - Create a NUL-terminated string from unterminated data
 * @s: The data to stringify
 * @len: The size of the data
 * @gfp: the GFP mask used in the kmalloc() call when allocating memory
 *
 * Return: newly allocated copy of @s with NUL-termination or %NULL in
 * case of error
 */
char *kmemdup_nul(const char *s, size_t len, gfp_t gfp)
{
    char *buf;

    if (!s)
        return NULL;

    buf = kmalloc_track_caller(len + 1, gfp);
    if (buf) {
        memcpy(buf, s, len);
        buf[len] = '\0';
    }
    return buf;
}
EXPORT_SYMBOL(kmemdup_nul);

/**
 * folio_mapped - Is this folio mapped into userspace?
 * @folio: The folio.
 *
 * Return: True if any page in this folio is referenced by user page tables.
 */
bool folio_mapped(struct folio *folio)
{
    long i, nr;

    if (!folio_test_large(folio))
        return atomic_read(&folio->_mapcount) >= 0;
    if (atomic_read(folio_mapcount_ptr(folio)) >= 0)
        return true;
    if (folio_test_hugetlb(folio))
        return false;

    nr = folio_nr_pages(folio);
    for (i = 0; i < nr; i++) {
        if (atomic_read(&folio_page(folio, i)->_mapcount) >= 0)
            return true;
    }
    return false;
}
EXPORT_SYMBOL(folio_mapped);

void __vma_link_list(struct mm_struct *mm, struct vm_area_struct *vma,
                     struct vm_area_struct *prev)
{
    struct vm_area_struct *next;

    vma->vm_prev = prev;
    if (prev) {
        next = prev->vm_next;
        prev->vm_next = vma;
    } else {
        next = mm->mmap;
        mm->mmap = vma;
    }
    vma->vm_next = next;
    if (next)
        next->vm_prev = vma;
}

void __vma_unlink_list(struct mm_struct *mm, struct vm_area_struct *vma)
{
    struct vm_area_struct *prev, *next;

    next = vma->vm_next;
    prev = vma->vm_prev;
    if (prev)
        prev->vm_next = next;
    else
        mm->mmap = next;
    if (next)
        next->vm_prev = prev;
}

/**
 * folio_mapping - Find the mapping where this folio is stored.
 * @folio: The folio.
 *
 * For folios which are in the page cache, return the mapping that this
 * page belongs to.  Folios in the swap cache return the swap mapping
 * this page is stored in (which is different from the mapping for the
 * swap file or swap device where the data is stored).
 *
 * You can call this for folios which aren't in the swap cache or page
 * cache and it will return NULL.
 */
struct address_space *folio_mapping(struct folio *folio)
{
    struct address_space *mapping;

    /* This happens if someone calls flush_dcache_page on slab page */
    if (unlikely(folio_test_slab(folio)))
        return NULL;

    if (unlikely(folio_test_swapcache(folio)))
        return swap_address_space(folio_swap_entry(folio));

    mapping = folio->mapping;
    if ((unsigned long)mapping & PAGE_MAPPING_ANON)
        return NULL;

    return (void *)((unsigned long)mapping & ~PAGE_MAPPING_FLAGS);
}
EXPORT_SYMBOL(folio_mapping);

#ifndef ARCH_IMPLEMENTS_FLUSH_DCACHE_FOLIO
void flush_dcache_folio(struct folio *folio)
{
    long i, nr = folio_nr_pages(folio);

    for (i = 0; i < nr; i++)
        flush_dcache_page(folio_page(folio, i));
}
EXPORT_SYMBOL(flush_dcache_folio);
#endif

/*
 * Leave enough space between the mmap area and the stack to honour ulimit in
 * the face of randomisation.
 */
#define MIN_GAP     (SZ_128M)
#define MAX_GAP     (STACK_TOP / 6 * 5)

static unsigned long
mmap_base(unsigned long rnd, struct rlimit *rlim_stack)
{
    unsigned long gap = rlim_stack->rlim_cur;
    unsigned long pad = stack_guard_gap;

    /* Account for stack randomization if necessary */
    if (current->flags & PF_RANDOMIZE)
        pad += (STACK_RND_MASK << PAGE_SHIFT);

    /* Values close to RLIM_INFINITY can overflow. */
    if (gap + pad > gap)
        gap += pad;

    if (gap < MIN_GAP)
        gap = MIN_GAP;
    else if (gap > MAX_GAP)
        gap = MAX_GAP;

    return PAGE_ALIGN(STACK_TOP - gap - rnd);
}

void arch_pick_mmap_layout(struct mm_struct *mm,
                           struct rlimit *rlim_stack)
{
    mm->mmap_base = mmap_base(0, rlim_stack);
    mm->get_unmapped_area = arch_get_unmapped_area_topdown;
}

unsigned long randomize_stack_top(unsigned long stack_top)
{
    unsigned long random_variable = 0;

    if (current->flags & PF_RANDOMIZE) {
#if 0
        random_variable = get_random_long();
        random_variable &= STACK_RND_MASK;
        random_variable <<= PAGE_SHIFT;
#endif
        panic("%s: END!\n", __func__);
    }
    return PAGE_ALIGN(stack_top) - random_variable;
}

unsigned long vm_mmap_pgoff(struct file *file, unsigned long addr,
                            unsigned long len, unsigned long prot,
                            unsigned long flag, unsigned long pgoff)
{
    unsigned long ret;
    struct mm_struct *mm = current->mm;
    unsigned long populate;
    LIST_HEAD(uf);

    if (mmap_write_lock_killable(mm))
        return -EINTR;
    ret = do_mmap(file, addr, len, prot, flag, pgoff, &populate, &uf);
    if (file && file->f_path.dentry) {
        printk("%s: file(%s) ret(%lx) addr(%lx, %lx) populate(%d)\n",
               __func__, file->f_path.dentry->d_name.name,
               ret, addr, len, populate);
    }
    mmap_write_unlock(mm);
    if (populate)
        mm_populate(ret, populate);

    return ret;
}

unsigned long vm_mmap(struct file *file, unsigned long addr,
                      unsigned long len, unsigned long prot,
                      unsigned long flag, unsigned long offset)
{
    if (unlikely(offset + PAGE_ALIGN(len) < offset))
        return -EINVAL;
    if (unlikely(offset_in_page(offset)))
        return -EINVAL;

    return vm_mmap_pgoff(file, addr, len, prot, flag,
                         offset >> PAGE_SHIFT);
}
EXPORT_SYMBOL(vm_mmap);

unsigned long arch_mmap_rnd(void)
{
    unsigned long rnd;

    rnd = get_random_long() & ((1UL << mmap_rnd_bits) - 1);

    return rnd << PAGE_SHIFT;
}

/**
 * folio_mapcount() - Calculate the number of mappings of this folio.
 * @folio: The folio.
 *
 * A large folio tracks both how many times the entire folio is mapped,
 * and how many times each individual page in the folio is mapped.
 * This function calculates the total number of times the folio is
 * mapped.
 *
 * Return: The number of times this folio is mapped.
 */
int folio_mapcount(struct folio *folio)
{
    int i, compound, nr, ret;

    if (likely(!folio_test_large(folio)))
        return atomic_read(&folio->_mapcount) + 1;

    compound = folio_entire_mapcount(folio);
    nr = folio_nr_pages(folio);
    if (folio_test_hugetlb(folio))
        return compound;
    ret = compound;
    for (i = 0; i < nr; i++)
        ret += atomic_read(&folio_page(folio, i)->_mapcount) + 1;
    /* File pages has compound_mapcount included in _mapcount */
    if (!folio_test_anon(folio))
        return ret - compound * nr;
    if (folio_test_double_map(folio))
        ret -= nr;
    panic("%s: END!\n", __func__);
    return ret;
}

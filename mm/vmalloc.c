// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 1993  Linus Torvalds
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  SMP-safe vmalloc/vfree/ioremap, Tigran Aivazian <tigran@veritas.com>, May 2000
 *  Major rework to support vmap/vunmap, Christoph Hellwig, SGI, August 2002
 *  Numa awareness, Christoph Lameter, SGI, June 2005
 *  Improving global KVA allocator, Uladzislau Rezki, Sony, May 2019
 */
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#if 0
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/set_memory.h>
#include <linux/debugobjects.h>
#include <linux/kallsyms.h>
#endif
#include <linux/list.h>
//#include <linux/notifier.h>
#include <linux/rbtree.h>
//#include <linux/xarray.h>
#include <linux/io.h>
#include <linux/rcupdate.h>
#include <linux/pfn.h>
#include <linux/atomic.h>
#include <linux/compiler.h>
#include <linux/memcontrol.h>
//#include <linux/llist.h>
#include <linux/bitops.h>
#include <linux/rbtree_augmented.h>
#include <linux/overflow.h>
#include <linux/pgtable.h>
#include <linux/uaccess.h>
#include <linux/hugetlb.h>
#include <linux/sched/mm.h>
#include <asm/tlbflush.h>
//#include <asm/shmparam.h>

#include "internal.h"
#include "pgalloc-track.h"

enum fit_type {
    NOTHING_FIT = 0,
    FL_FIT_TYPE = 1,    /* full fit */
    LE_FIT_TYPE = 2,    /* left edge fit */
    RE_FIT_TYPE = 3,    /* right edge fit */
    NE_FIT_TYPE = 4     /* no edge fit */
};

static DEFINE_SPINLOCK(vmap_area_lock);
static DEFINE_SPINLOCK(free_vmap_area_lock);

/* Export for kexec only */
LIST_HEAD(vmap_area_list);
static struct rb_root vmap_area_root = RB_ROOT;
static bool vmap_initialized __read_mostly;

static struct vm_struct *vmlist __initdata;

/*
 * This kmem_cache is used for vmap_area objects. Instead of
 * allocating from slab we reuse an object from this cache to
 * make things faster. Especially in "no edge" splitting of
 * free block.
 */
static struct kmem_cache *vmap_area_cachep;

/*
 * This linked list is used in pair with free_vmap_area_root.
 * It gives O(1) access to prev/next to perform fast coalescing.
 */
static LIST_HEAD(free_vmap_area_list);

/*
 * This augment red-black tree represents the free vmap space.
 * All vmap_area objects in this tree are sorted by va->va_start
 * address. It is used for allocation and merging when a vmap
 * object is released.
 *
 * Each vmap_area node contains a maximum available free block
 * of its sub-tree, right or left. Therefore it is possible to
 * find a lowest match of free area.
 */
static struct rb_root free_vmap_area_root = RB_ROOT;

/*
 * Preload a CPU with one object for "no edge" split case. The
 * aim is to get rid of allocations from the atomic context, thus
 * to use more permissive allocation masks.
 */
static DEFINE_PER_CPU(struct vmap_area *, ne_fit_preload_node);

static struct rb_root purge_vmap_area_root = RB_ROOT;
static LIST_HEAD(purge_vmap_area_list);
static DEFINE_SPINLOCK(purge_vmap_area_lock);

static atomic_long_t nr_vmalloc_pages;

static const unsigned int ioremap_max_page_shift = PAGE_SHIFT;

static inline unsigned int vm_area_page_order(struct vm_struct *vm)
{
    return 0;
}

static inline void set_vm_area_page_order(struct vm_struct *vm,
                                          unsigned int order)
{
    BUG_ON(order != 0);
}

static void __vunmap(const void *addr, int deallocate_pages)
{
    panic("%s: NO implementation!\n", __func__);
}

static inline void __vfree_deferred(const void *addr)
{
    panic("%s: NO implementation!\n", __func__);

#if 0
    /*
     * Use raw_cpu_ptr() because this can be called from preemptible
     * context. Preemption is absolutely fine here, because the llist_add()
     * implementation is lockless, so it works even if we are adding to
     * another cpu's list. schedule_work() should be fine with this too.
     */
    struct vfree_deferred *p = raw_cpu_ptr(&vfree_deferred);

    if (llist_add((struct llist_node *)addr, &p->list))
        schedule_work(&p->wq);
#endif
}

static void __vfree(const void *addr)
{
    if (unlikely(in_interrupt()))
        __vfree_deferred(addr);
    else
        __vunmap(addr, 1);
}

/**
 * vfree - Release memory allocated by vmalloc()
 * @addr:  Memory base address
 *
 * Free the virtually continuous memory area starting at @addr, as obtained
 * from one of the vmalloc() family of APIs.  This will usually also free the
 * physical memory underlying the virtual allocation, but that memory is
 * reference counted, so it will not be freed until the last user goes away.
 *
 * If @addr is NULL, no operation is performed.
 *
 * Context:
 * May sleep if called *not* from interrupt context.
 * Must not be called in NMI context (strictly speaking, it could be
 * if we have CONFIG_ARCH_HAVE_NMI_SAFE_CMPXCHG, but making the calling
 * conventions for vfree() arch-dependent would be a really bad idea).
 */
void vfree(const void *addr)
{
    BUG_ON(in_nmi());

    might_sleep_if(!in_interrupt());

    if (!addr)
        return;

    __vfree(addr);
}
EXPORT_SYMBOL(vfree);

/*
 * lazy_max_pages is the maximum amount of virtual address space we gather up
 * before attempting to purge with a TLB flush.
 *
 * There is a tradeoff here: a larger number will cover more kernel page tables
 * and take slightly longer to purge, but it will linearly reduce the number of
 * global TLB flushes that must be performed. It would seem natural to scale
 * this number up linearly with the number of CPUs (because vmapping activity
 * could also scale linearly with the number of CPUs), however it is likely
 * that in practice, workloads might be constrained in other ways that mean
 * vmap activity will not scale linearly with CPUs. Also, I want to be
 * conservative and not introduce a big latency on huge systems, so go with
 * a less aggressive log scale. It will still be an improvement over the old
 * code, and it will be simple to change the scale factor if we find that it
 * becomes a problem on bigger systems.
 */
static unsigned long lazy_max_pages(void)
{
    unsigned int log;

    log = fls(num_online_cpus());

    return log * (32UL * 1024 * 1024 / PAGE_SIZE);
}

static atomic_long_t vmap_lazy_nr = ATOMIC_LONG_INIT(0);

static __always_inline unsigned long
va_size(struct vmap_area *va)
{
    return (va->va_end - va->va_start);
}

static __always_inline unsigned long
get_subtree_max_size(struct rb_node *node)
{
    struct vmap_area *va;

    va = rb_entry_safe(node, struct vmap_area, rb_node);
    return va ? va->subtree_max_size : 0;
}

RB_DECLARE_CALLBACKS_MAX(static, free_vmap_area_rb_augment_cb,
                         struct vmap_area, rb_node,
                         unsigned long, subtree_max_size, va_size)

static struct vmap_area *__find_vmap_area(unsigned long addr)
{
    struct rb_node *n = vmap_area_root.rb_node;

    addr = (unsigned long)((void *)addr);

    while (n) {
        struct vmap_area *va;

        va = rb_entry(n, struct vmap_area, rb_node);
        if (addr < va->va_start)
            n = n->rb_left;
        else if (addr >= va->va_end)
            n = n->rb_right;
        else
            return va;
    }

    return NULL;
}

static struct vmap_area *find_vmap_area(unsigned long addr)
{
    struct vmap_area *va;

    spin_lock(&vmap_area_lock);
    va = __find_vmap_area(addr);
    spin_unlock(&vmap_area_lock);

    return va;
}

/**
 * find_vm_area - find a continuous kernel virtual area
 * @addr:     base address
 *
 * Search for the kernel VM area starting at @addr, and return it.
 * It is up to the caller to do all required locking to keep the returned
 * pointer valid.
 *
 * Return: the area descriptor on success or %NULL on failure.
 */
struct vm_struct *find_vm_area(const void *addr)
{
    struct vmap_area *va;

    va = find_vmap_area((unsigned long)addr);
    if (!va)
        return NULL;

    return va->vm;
}

/*
 * This function returns back addresses of parent node
 * and its left or right link for further processing.
 *
 * Otherwise NULL is returned. In that case all further
 * steps regarding inserting of conflicting overlap range
 * have to be declined and actually considered as a bug.
 */
static __always_inline struct rb_node **
find_va_links(struct vmap_area *va, struct rb_root *root, struct rb_node *from,
              struct rb_node **parent)
{
    struct vmap_area *tmp_va;
    struct rb_node **link;

    if (root) {
        link = &root->rb_node;
        if (unlikely(!*link)) {
            *parent = NULL;
            return link;
        }
    } else {
        link = &from;
    }

    /*
     * Go to the bottom of the tree. When we hit the last point
     * we end up with parent rb_node and correct direction, i name
     * it link, where the new va->rb_node will be attached to.
     */
    do {
        tmp_va = rb_entry(*link, struct vmap_area, rb_node);

        /*
         * During the traversal we also do some sanity check.
         * Trigger the BUG() if there are sides(left/right)
         * or full overlaps.
         */
        if (va->va_start < tmp_va->va_end && va->va_end <= tmp_va->va_start)
            link = &(*link)->rb_left;
        else if (va->va_end > tmp_va->va_start &&
                 va->va_start >= tmp_va->va_end)
            link = &(*link)->rb_right;
        else {
            WARN(1, "vmalloc bug: 0x%lx-0x%lx overlaps with 0x%lx-0x%lx\n",
                 va->va_start, va->va_end, tmp_va->va_start, tmp_va->va_end);

            return NULL;
        }
    } while (*link);

    *parent = &tmp_va->rb_node;
    return link;
}

static __always_inline void
link_va(struct vmap_area *va, struct rb_root *root, struct rb_node *parent,
        struct rb_node **link, struct list_head *head)
{
    /*
     * VA is still not in the list, but we can
     * identify its future previous list_head node.
     */
    if (likely(parent)) {
        head = &rb_entry(parent, struct vmap_area, rb_node)->list;
        if (&parent->rb_right != link)
            head = head->prev;
    }

    /* Insert to the rb-tree */
    rb_link_node(&va->rb_node, parent, link);
    if (root == &free_vmap_area_root) {
        /*
         * Some explanation here. Just perform simple insertion
         * to the tree. We do not set va->subtree_max_size to
         * its current size before calling rb_insert_augmented().
         * It is because of we populate the tree from the bottom
         * to parent levels when the node _is_ in the tree.
         *
         * Therefore we set subtree_max_size to zero after insertion,
         * to let __augment_tree_propagate_from() puts everything to
         * the correct order later on.
         */
        rb_insert_augmented(&va->rb_node, root, &free_vmap_area_rb_augment_cb);
        va->subtree_max_size = 0;
    } else {
        rb_insert_color(&va->rb_node, root);
    }

    /* Address-sort this list */
    list_add(&va->list, head);
}

static __always_inline void
unlink_va(struct vmap_area *va, struct rb_root *root)
{
    if (WARN_ON(RB_EMPTY_NODE(&va->rb_node)))
        return;

    if (root == &free_vmap_area_root)
        rb_erase_augmented(&va->rb_node, root, &free_vmap_area_rb_augment_cb);
    else
        rb_erase(&va->rb_node, root);

    list_del(&va->list);
    RB_CLEAR_NODE(&va->rb_node);
}

static void
insert_vmap_area(struct vmap_area *va,
                 struct rb_root *root, struct list_head *head)
{
    struct rb_node **link;
    struct rb_node *parent;

    link = find_va_links(va, root, NULL, &parent);
    if (link)
        link_va(va, root, parent, link, head);
}

/*
 * This function populates subtree_max_size from bottom to upper
 * levels starting from VA point. The propagation must be done
 * when VA size is modified by changing its va_start/va_end. Or
 * in case of newly inserting of VA to the tree.
 *
 * It means that __augment_tree_propagate_from() must be called:
 * - After VA has been inserted to the tree(free path);
 * - After VA has been shrunk(allocation path);
 * - After VA has been increased(merging path).
 *
 * Please note that, it does not mean that upper parent nodes
 * and their subtree_max_size are recalculated all the time up
 * to the root node.
 *
 *       4--8
 *        /\
 *       /  \
 *      /    \
 *    2--2  8--8
 *
 * For example if we modify the node 4, shrinking it to 2, then
 * no any modification is required. If we shrink the node 2 to 1
 * its subtree_max_size is updated only, and set to 1. If we shrink
 * the node 8 to 6, then its subtree_max_size is set to 6 and parent
 * node becomes 4--6.
 */
static __always_inline void
augment_tree_propagate_from(struct vmap_area *va)
{
    /*
     * Populate the tree from bottom towards the root until
     * the calculated maximum available size of checked node
     * is equal to its current one.
     */
    free_vmap_area_rb_augment_cb_propagate(&va->rb_node, NULL);
}

static void
insert_vmap_area_augment(struct vmap_area *va, struct rb_node *from,
                         struct rb_root *root, struct list_head *head)
{
    struct rb_node **link;
    struct rb_node *parent;

    if (from)
        link = find_va_links(va, NULL, from, &parent);
    else
        link = find_va_links(va, root, NULL, &parent);

    if (link) {
        link_va(va, root, parent, link, head);
        augment_tree_propagate_from(va);
    }
}

static void vmap_init_free_space(void)
{
    struct vmap_area *busy, *free;
    unsigned long vmap_start = 1;
    const unsigned long vmap_end = ULONG_MAX;

    /*
     *     B     F     B     B     B     F
     * -|-----|.....|-----|-----|-----|.....|-
     *  |           The KVA space           |
     *  |<--------------------------------->|
     */
    list_for_each_entry(busy, &vmap_area_list, list) {
        if (busy->va_start - vmap_start > 0) {
            free = kmem_cache_zalloc(vmap_area_cachep, GFP_NOWAIT);
            if (!WARN_ON_ONCE(!free)) {
                free->va_start = vmap_start;
                free->va_end = busy->va_start;

                insert_vmap_area_augment(free, NULL, &free_vmap_area_root,
                                         &free_vmap_area_list);
            }
        }

        vmap_start = busy->va_end;
    }

    if (vmap_end - vmap_start > 0) {
        free = kmem_cache_zalloc(vmap_area_cachep, GFP_NOWAIT);
        if (!WARN_ON_ONCE(!free)) {
            free->va_start = vmap_start;
            free->va_end = vmap_end;

            insert_vmap_area_augment(free, NULL, &free_vmap_area_root,
                                     &free_vmap_area_list);
        }
    }
}

static inline void
preload_this_cpu_lock(spinlock_t *lock, gfp_t gfp_mask, int node)
{
    struct vmap_area *va = NULL;

    /*
     * Preload this CPU with one extra vmap_area object. It is used
     * when fit type of free area is NE_FIT_TYPE. It guarantees that
     * a CPU that does an allocation is preloaded.
     *
     * We do it in non-atomic context, thus it allows us to use more
     * permissive allocation masks to be more stable under low memory
     * condition and high memory pressure.
     */
    if (!this_cpu_read(ne_fit_preload_node))
        va = kmem_cache_alloc_node(vmap_area_cachep, gfp_mask, node);

    spin_lock(lock);

    if (va && __this_cpu_cmpxchg(ne_fit_preload_node, NULL, va))
        kmem_cache_free(vmap_area_cachep, va);
}

static __always_inline enum fit_type
classify_va_fit_type(struct vmap_area *va,
                     unsigned long nva_start_addr, unsigned long size)
{
    enum fit_type type;

    /* Check if it is within VA. */
    if (nva_start_addr < va->va_start || nva_start_addr + size > va->va_end)
        return NOTHING_FIT;

    /* Now classify. */
    if (va->va_start == nva_start_addr) {
        if (va->va_end == nva_start_addr + size)
            type = FL_FIT_TYPE;
        else
            type = LE_FIT_TYPE;
    } else if (va->va_end == nva_start_addr + size) {
        type = RE_FIT_TYPE;
    } else {
        type = NE_FIT_TYPE;
    }

    return type;
}

static __always_inline int
adjust_va_to_fit_type(struct vmap_area *va,
                      unsigned long nva_start_addr, unsigned long size,
                      enum fit_type type)
{
    struct vmap_area *lva = NULL;

    if (type == FL_FIT_TYPE) {
        /*
         * No need to split VA, it fully fits.
         *
         * |               |
         * V      NVA      V
         * |---------------|
         */
        unlink_va(va, &free_vmap_area_root);
        kmem_cache_free(vmap_area_cachep, va);
    } else if (type == LE_FIT_TYPE) {
        /*
         * Split left edge of fit VA.
         *
         * |       |
         * V  NVA  V   R
         * |-------|-------|
         */
        va->va_start += size;
    } else if (type == RE_FIT_TYPE) {
        /*
         * Split right edge of fit VA.
         *
         *         |       |
         *     L   V  NVA  V
         * |-------|-------|
         */
        va->va_end = nva_start_addr;
    } else if (type == NE_FIT_TYPE) {
        /*
         * Split no edge of fit VA.
         *
         *     |       |
         *   L V  NVA  V R
         * |---|-------|---|
         */
        lva = __this_cpu_xchg(ne_fit_preload_node, NULL);
        if (unlikely(!lva)) {
            /*
             * For percpu allocator we do not do any pre-allocation
             * and leave it as it is. The reason is it most likely
             * never ends up with NE_FIT_TYPE splitting. In case of
             * percpu allocations offsets and sizes are aligned to
             * fixed align request, i.e. RE_FIT_TYPE and FL_FIT_TYPE
             * are its main fitting cases.
             *
             * There are a few exceptions though, as an example it is
             * a first allocation (early boot up) when we have "one"
             * big free space that has to be split.
             *
             * Also we can hit this path in case of regular "vmap"
             * allocations, if "this" current CPU was not preloaded.
             * See the comment in alloc_vmap_area() why. If so, then
             * GFP_NOWAIT is used instead to get an extra object for
             * split purpose. That is rare and most time does not
             * occur.
             *
             * What happens if an allocation gets failed. Basically,
             * an "overflow" path is triggered to purge lazily freed
             * areas to free some memory, then, the "retry" path is
             * triggered to repeat one more time. See more details
             * in alloc_vmap_area() function.
             */
            lva = kmem_cache_alloc(vmap_area_cachep, GFP_NOWAIT);
            if (!lva)
                return -1;
        }

        /*
         * Build the remainder.
         */
        lva->va_start = va->va_start;
        lva->va_end = nva_start_addr;

        /*
         * Shrink this VA to remaining size.
         */
        va->va_start = nva_start_addr + size;
    } else {
        return -1;
    }

    if (type != FL_FIT_TYPE) {
        augment_tree_propagate_from(va);

        if (lva)    /* type == NE_FIT_TYPE */
            insert_vmap_area_augment(lva, &va->rb_node,
                                     &free_vmap_area_root,
                                     &free_vmap_area_list);
    }

    return 0;
}

static __always_inline bool
is_within_this_va(struct vmap_area *va, unsigned long size,
                  unsigned long align, unsigned long vstart)
{
    unsigned long nva_start_addr;

    if (va->va_start > vstart)
        nva_start_addr = ALIGN(va->va_start, align);
    else
        nva_start_addr = ALIGN(vstart, align);

    /* Can be overflowed due to big size or alignment. */
    if (nva_start_addr + size < nva_start_addr || nva_start_addr < vstart)
        return false;

    return (nva_start_addr + size <= va->va_end);
}

/*
 * Find the first free block(lowest start address) in the tree,
 * that will accomplish the request corresponding to passing
 * parameters. Please note, with an alignment bigger than PAGE_SIZE,
 * a search length is adjusted to account for worst case alignment
 * overhead.
 */
static __always_inline struct vmap_area *
find_vmap_lowest_match(unsigned long size, unsigned long align,
                       unsigned long vstart, bool adjust_search_size)
{
    struct vmap_area *va;
    struct rb_node *node;
    unsigned long length;

    /* Start from the root. */
    node = free_vmap_area_root.rb_node;

    /* Adjust the search size for alignment overhead. */
    length = adjust_search_size ? size + align - 1 : size;

    while (node) {
        va = rb_entry(node, struct vmap_area, rb_node);

        if (get_subtree_max_size(node->rb_left) >= length &&
            vstart < va->va_start) {
            node = node->rb_left;
        } else {
            if (is_within_this_va(va, size, align, vstart))
                return va;

            /*
             * Does not make sense to go deeper towards the right
             * sub-tree if it does not have a free block that is
             * equal or bigger to the requested search length.
             */
            if (get_subtree_max_size(node->rb_right) >= length) {
                node = node->rb_right;
                continue;
            }

            /*
             * OK. We roll back and find the first right sub-tree,
             * that will satisfy the search criteria. It can happen
             * due to "vstart" restriction or an alignment overhead
             * that is bigger then PAGE_SIZE.
             */
            while ((node = rb_parent(node))) {
                va = rb_entry(node, struct vmap_area, rb_node);
                if (is_within_this_va(va, size, align, vstart))
                    return va;

                if (get_subtree_max_size(node->rb_right) >= length &&
                    vstart <= va->va_start) {
                    /*
                     * Shift the vstart forward. Please note, we update it with
                     * parent's start address adding "1" because we do not want
                     * to enter same sub-tree after it has already been checked
                     * and no suitable free block found there.
                     */
                    vstart = va->va_start + 1;
                    node = node->rb_right;
                    break;
                }
            }
        }
    }

    return NULL;
}

/*
 * Returns a start address of the newly allocated area, if success.
 * Otherwise a vend is returned that indicates failure.
 */
static __always_inline unsigned long
__alloc_vmap_area(unsigned long size, unsigned long align,
                  unsigned long vstart, unsigned long vend)
{
    bool adjust_search_size = true;
    unsigned long nva_start_addr;
    struct vmap_area *va;
    enum fit_type type;
    int ret;

    /*
     * Do not adjust when:
     *   a) align <= PAGE_SIZE, because it does not make any sense.
     *      All blocks(their start addresses) are at least PAGE_SIZE
     *      aligned anyway;
     *   b) a short range where a requested size corresponds to exactly
     *      specified [vstart:vend] interval and an alignment > PAGE_SIZE.
     *      With adjusted search length an allocation would not succeed.
     */
    if (align <= PAGE_SIZE || (align > PAGE_SIZE && (vend - vstart) == size))
        adjust_search_size = false;

    va = find_vmap_lowest_match(size, align, vstart, adjust_search_size);
    if (unlikely(!va))
        return vend;

    if (va->va_start > vstart)
        nva_start_addr = ALIGN(va->va_start, align);
    else
        nva_start_addr = ALIGN(vstart, align);

    /* Check the "vend" restriction. */
    if (nva_start_addr + size > vend)
        return vend;

    /* Classify what we have found. */
    type = classify_va_fit_type(va, nva_start_addr, size);
    if (WARN_ON_ONCE(type == NOTHING_FIT))
        return vend;

    /* Update the free vmap_area. */
    ret = adjust_va_to_fit_type(va, nva_start_addr, size, type);
    if (ret)
        return vend;

    return nva_start_addr;
}

/*
 * Allocate a region of KVA of the specified size and alignment, within the
 * vstart and vend.
 */
static struct vmap_area *
alloc_vmap_area(unsigned long size, unsigned long align,
                unsigned long vstart, unsigned long vend,
                int node, gfp_t gfp_mask)
{
    struct vmap_area *va;
    unsigned long freed;
    unsigned long addr;
    int purged = 0;
    int ret;

    BUG_ON(!size);
    BUG_ON(offset_in_page(size));
    BUG_ON(!is_power_of_2(align));

    if (unlikely(!vmap_initialized))
        return ERR_PTR(-EBUSY);

    might_sleep();
    gfp_mask = gfp_mask & GFP_RECLAIM_MASK;

    va = kmem_cache_alloc_node(vmap_area_cachep, gfp_mask, node);
    if (unlikely(!va))
        return ERR_PTR(-ENOMEM);

 retry:
    preload_this_cpu_lock(&free_vmap_area_lock, gfp_mask, node);
    addr = __alloc_vmap_area(size, align, vstart, vend);
    spin_unlock(&free_vmap_area_lock);

    /*
     * If an allocation fails, the "vend" address is
     * returned. Therefore trigger the overflow path.
     */
    if (unlikely(addr == vend))
        goto overflow;

    va->va_start = addr;
    va->va_end = addr + size;
    va->vm = NULL;

    spin_lock(&vmap_area_lock);
    insert_vmap_area(va, &vmap_area_root, &vmap_area_list);
    spin_unlock(&vmap_area_lock);

    BUG_ON(!IS_ALIGNED(va->va_start, align));
    BUG_ON(va->va_start < vstart);
    BUG_ON(va->va_end > vend);

    return va;

 overflow:
#if 0
    if (!purged) {
        purge_vmap_area_lazy();
        purged = 1;
        goto retry;
    }

    freed = 0;
    blocking_notifier_call_chain(&vmap_notify_list, 0, &freed);

    if (freed > 0) {
        purged = 0;
        goto retry;
    }

    if (!(gfp_mask & __GFP_NOWARN) && printk_ratelimit())
        pr_warn("vmap allocation for size %lu failed: "
                "use vmalloc=<size> to increase size\n", size);
#endif

    kmem_cache_free(vmap_area_cachep, va);
    return ERR_PTR(-EBUSY);
}

static inline void
setup_vmalloc_vm_locked(struct vm_struct *vm, struct vmap_area *va,
                        unsigned long flags, const void *caller)
{
    vm->flags = flags;
    vm->addr = (void *)va->va_start;
    vm->size = va->va_end - va->va_start;
    vm->caller = caller;
    va->vm = vm;
}

static void setup_vmalloc_vm(struct vm_struct *vm, struct vmap_area *va,
                             unsigned long flags, const void *caller)
{
    spin_lock(&vmap_area_lock);
    setup_vmalloc_vm_locked(vm, va, flags, caller);
    spin_unlock(&vmap_area_lock);
}

static void clear_vm_uninitialized_flag(struct vm_struct *vm)
{
    /*
     * Before removing VM_UNINITIALIZED,
     * we should make sure that vm has proper values.
     * Pair with smp_rmb() in show_numa_info().
     */
    smp_wmb();
    vm->flags &= ~VM_UNINITIALIZED;
}

static struct vm_struct *
__get_vm_area_node(unsigned long size, unsigned long align,
                   unsigned long shift, unsigned long flags,
                   unsigned long start, unsigned long end, int node,
                   gfp_t gfp_mask, const void *caller)
{
    struct vmap_area *va;
    struct vm_struct *area;
    unsigned long requested_size = size;

    BUG_ON(in_interrupt());
    size = ALIGN(size, 1ul << shift);
    if (unlikely(!size))
        return NULL;

    if (flags & VM_IOREMAP)
        align = 1ul << clamp_t(int, get_count_order_long(size),
                               PAGE_SHIFT, IOREMAP_MAX_ORDER);

    area = kzalloc_node(sizeof(*area), gfp_mask & GFP_RECLAIM_MASK, node);
    if (unlikely(!area))
        return NULL;

    if (!(flags & VM_NO_GUARD))
        size += PAGE_SIZE;

    va = alloc_vmap_area(size, align, start, end, node, gfp_mask);
    if (IS_ERR(va)) {
        kfree(area);
        return NULL;
    }

    setup_vmalloc_vm(area, va, flags, caller);

    return area;
}

static void vunmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
                             pgtbl_mod_mask *mask)
{
    pte_t *pte;

    pte = pte_offset_kernel(pmd, addr);
    do {
        pte_t ptent = ptep_get_and_clear(&init_mm, addr, pte);
        WARN_ON(!pte_none(ptent) && !pte_present(ptent));
    } while (pte++, addr += PAGE_SIZE, addr != end);
    *mask |= PGTBL_PTE_MODIFIED;
}

static void vunmap_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
                             pgtbl_mod_mask *mask)
{
    pmd_t *pmd;
    unsigned long next;

    pmd = pmd_offset(pud, addr);
    do {
        next = pmd_addr_end(addr, end);

        if (pmd_bad(*pmd))
            *mask |= PGTBL_PMD_MODIFIED;

        if (pmd_none_or_clear_bad(pmd))
            continue;
        vunmap_pte_range(pmd, addr, next, mask);

        cond_resched();
    } while (pmd++, addr = next, addr != end);
}

static void vunmap_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end,
                 pgtbl_mod_mask *mask)
{
    pud_t *pud;
    unsigned long next;

    pud = pud_offset(p4d, addr);
    do {
        next = pud_addr_end(addr, end);

        if (pud_bad(*pud))
            *mask |= PGTBL_PUD_MODIFIED;

        if (pud_none_or_clear_bad(pud))
            continue;
        vunmap_pmd_range(pud, addr, next, mask);
    } while (pud++, addr = next, addr != end);
}

static void
vunmap_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
                 pgtbl_mod_mask *mask)
{
    p4d_t *p4d;
    unsigned long next;

    p4d = p4d_offset(pgd, addr);
    do {
        next = p4d_addr_end(addr, end);

        if (p4d_bad(*p4d))
            *mask |= PGTBL_P4D_MODIFIED;

        if (p4d_none_or_clear_bad(p4d))
            continue;
        vunmap_pud_range(p4d, addr, next, mask);
    } while (p4d++, addr = next, addr != end);
}

/*
 * vunmap_range_noflush is similar to vunmap_range, but does not
 * flush caches or TLBs.
 *
 * The caller is responsible for calling flush_cache_vmap() before calling
 * this function, and flush_tlb_kernel_range after it has returned
 * successfully (and before the addresses are expected to cause a page fault
 * or be re-mapped for something else, if TLB flushes are being delayed or
 * coalesced).
 *
 * This is an internal function only. Do not use outside mm/.
 */
void vunmap_range_noflush(unsigned long start, unsigned long end)
{
    unsigned long next;
    pgd_t *pgd;
    unsigned long addr = start;
    pgtbl_mod_mask mask = 0;

    BUG_ON(addr >= end);
    pgd = pgd_offset_k(addr);
    do {
        next = pgd_addr_end(addr, end);
        if (pgd_bad(*pgd))
            mask |= PGTBL_PGD_MODIFIED;
        if (pgd_none_or_clear_bad(pgd))
            continue;
        vunmap_p4d_range(pgd, addr, next, &mask);
    } while (pgd++, addr = next, addr != end);
}

/*
 * Merge de-allocated chunk of VA memory with previous
 * and next free blocks. If coalesce is not done a new
 * free area is inserted. If VA has been merged, it is
 * freed.
 *
 * Please note, it can return NULL in case of overlap
 * ranges, followed by WARN() report. Despite it is a
 * buggy behaviour, a system can be alive and keep
 * ongoing.
 */
static __always_inline struct vmap_area *
merge_or_add_vmap_area(struct vmap_area *va,
                       struct rb_root *root, struct list_head *head)
{
    panic("%s: END!\n", __func__);
}

static __always_inline struct vmap_area *
merge_or_add_vmap_area_augment(struct vmap_area *va,
                               struct rb_root *root, struct list_head *head)
{
    va = merge_or_add_vmap_area(va, root, head);
    if (va)
        augment_tree_propagate_from(va);

    return va;
}


/*
 * Free a vmap area, caller ensuring that the area has been unmapped
 * and flush_cache_vunmap had been called for the correct range
 * previously.
 */
static void free_vmap_area_noflush(struct vmap_area *va)
{
    unsigned long nr_lazy;

    spin_lock(&vmap_area_lock);
    unlink_va(va, &vmap_area_root);
    spin_unlock(&vmap_area_lock);

    nr_lazy = atomic_long_add_return((va->va_end - va->va_start) >> PAGE_SHIFT,
                                     &vmap_lazy_nr);

    /*
     * Merge or place it to the purge tree/list.
     */
    spin_lock(&purge_vmap_area_lock);
    merge_or_add_vmap_area(va, &purge_vmap_area_root, &purge_vmap_area_list);
    spin_unlock(&purge_vmap_area_lock);

#if 0
    /* After this point, we may free va at any time */
    if (unlikely(nr_lazy > lazy_max_pages()))
        schedule_work(&drain_vmap_work);
#endif
}

/*
 * Free and unmap a vmap area
 */
static void free_unmap_vmap_area(struct vmap_area *va)
{
    vunmap_range_noflush(va->va_start, va->va_end);

    free_vmap_area_noflush(va);
}

/**
 * remove_vm_area - find and remove a continuous kernel virtual area
 * @addr:       base address
 *
 * Search for the kernel VM area starting at @addr, and remove it.
 * This function returns the found VM area, but using it is NOT safe
 * on SMP machines, except for its size or flags.
 *
 * Return: the area descriptor on success or %NULL on failure.
 */
struct vm_struct *remove_vm_area(const void *addr)
{
    struct vmap_area *va;

    might_sleep();

    spin_lock(&vmap_area_lock);
    va = __find_vmap_area((unsigned long)addr);
    if (va && va->vm) {
        struct vm_struct *vm = va->vm;

        va->vm = NULL;
        spin_unlock(&vmap_area_lock);
        free_unmap_vmap_area(va);
        return vm;
    }

    spin_unlock(&vmap_area_lock);
    return NULL;
}

void free_vm_area(struct vm_struct *area)
{
    struct vm_struct *ret;
    ret = remove_vm_area(area->addr);
    BUG_ON(ret != area);
    kfree(area);
}
EXPORT_SYMBOL_GPL(free_vm_area);

static inline unsigned int
vm_area_alloc_pages(gfp_t gfp, int nid, unsigned int order,
                    unsigned int nr_pages, struct page **pages)
{
    unsigned int nr_allocated = 0;
    struct page *page;
    int i;

    /*
     * For order-0 pages we make use of bulk allocator, if
     * the page array is partly or not at all populated due
     * to fails, fallback to a single page allocator that is
     * more permissive.
     */
    if (!order) {
        gfp_t bulk_gfp = gfp & ~__GFP_NOFAIL;

        while (nr_allocated < nr_pages) {
            unsigned int nr, nr_pages_request;

            /*
             * A maximum allowed request is hard-coded and is 100
             * pages per call. That is done in order to prevent a
             * long preemption off scenario in the bulk-allocator
             * so the range is [1:100].
             */
            nr_pages_request = min(100U, nr_pages - nr_allocated);

            nr = alloc_pages_bulk_array_node(bulk_gfp, nid, nr_pages_request,
                                             pages + nr_allocated);

            nr_allocated += nr;
            cond_resched();

            /*
             * If zero or pages were obtained partly,
             * fallback to a single page allocator.
             */
            if (nr != nr_pages_request)
                break;
        }
    }

    /* High-order pages or fallback path if "bulk" fails. */

    while (nr_allocated < nr_pages) {
#if 0
        if (fatal_signal_pending(current))
            break;
#endif

        if (nid == NUMA_NO_NODE)
            page = alloc_pages(gfp, order);
        else
            page = alloc_pages_node(nid, gfp, order);
        if (unlikely(!page))
            break;
        /*
         * Higher order allocations must be able to be treated as
         * indepdenent small pages by callers (as they can with
         * small-page vmallocs). Some drivers do their own refcounting
         * on vmalloc_to_page() pages, some use page->mapping,
         * page->lru, etc.
         */
        if (order) {
            panic("%s: order is NOT ZERO!\n", __func__);
            //split_page(page, order);
        }

        /*
         * Careful, we allocate and map page-order pages, but
         * tracking is done per PAGE_SIZE page so as to keep the
         * vm_struct APIs independent of the physical/mapped size.
         */
        for (i = 0; i < (1U << order); i++)
            pages[nr_allocated + i] = page + i;

        cond_resched();
        nr_allocated += 1U << order;
    }

    return nr_allocated;
}

static int
vmap_pages_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
                     pgprot_t prot, struct page **pages, int *nr,
                     pgtbl_mod_mask *mask)
{
    pte_t *pte;

    /*
     * nr is a running index into the array which helps higher level
     * callers keep track of where we're up to.
     */

    pte = pte_alloc_kernel_track(pmd, addr, mask);
    if (!pte)
        return -ENOMEM;
    do {
        struct page *page = pages[*nr];

        if (WARN_ON(!pte_none(*pte)))
            return -EBUSY;
        if (WARN_ON(!page))
            return -ENOMEM;
        set_pte_at(&init_mm, addr, pte, mk_pte(page, prot));
        (*nr)++;
    } while (pte++, addr += PAGE_SIZE, addr != end);
    *mask |= PGTBL_PTE_MODIFIED;
    return 0;
}

static int
vmap_pages_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
                     pgprot_t prot, struct page **pages, int *nr,
                     pgtbl_mod_mask *mask)
{
    pmd_t *pmd;
    unsigned long next;

    pmd = pmd_alloc_track(&init_mm, pud, addr, mask);
    if (!pmd)
        return -ENOMEM;
    do {
        next = pmd_addr_end(addr, end);
        if (vmap_pages_pte_range(pmd, addr, next, prot, pages, nr, mask))
            return -ENOMEM;
    } while (pmd++, addr = next, addr != end);
    return 0;
}

static int
vmap_pages_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end,
                     pgprot_t prot, struct page **pages, int *nr,
                     pgtbl_mod_mask *mask)
{
    pud_t *pud;
    unsigned long next;

    pud = pud_alloc_track(&init_mm, p4d, addr, mask);
    if (!pud)
        return -ENOMEM;
    do {
        next = pud_addr_end(addr, end);
        if (vmap_pages_pmd_range(pud, addr, next, prot, pages, nr, mask))
            return -ENOMEM;
    } while (pud++, addr = next, addr != end);
    return 0;
}

static int
vmap_pages_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
                     pgprot_t prot, struct page **pages, int *nr,
                     pgtbl_mod_mask *mask)
{
    p4d_t *p4d;
    unsigned long next;

    p4d = p4d_alloc_track(&init_mm, pgd, addr, mask);
    if (!p4d)
        return -ENOMEM;
    do {
        next = p4d_addr_end(addr, end);
        if (vmap_pages_pud_range(p4d, addr, next, prot, pages, nr, mask))
            return -ENOMEM;
    } while (p4d++, addr = next, addr != end);
    return 0;
}

static int
vmap_small_pages_range_noflush(unsigned long addr, unsigned long end,
                               pgprot_t prot, struct page **pages)
{
    unsigned long start = addr;
    pgd_t *pgd;
    unsigned long next;
    int err = 0;
    int nr = 0;
    pgtbl_mod_mask mask = 0;

    BUG_ON(addr >= end);
    pgd = pgd_offset_k(addr);
    do {
        next = pgd_addr_end(addr, end);
        if (pgd_bad(*pgd))
            mask |= PGTBL_PGD_MODIFIED;
        err = vmap_pages_p4d_range(pgd, addr, next, prot, pages, &nr, &mask);
        if (err)
            return err;
    } while (pgd++, addr = next, addr != end);

    return 0;
}

/*
 * vmap_pages_range_noflush is similar to vmap_pages_range, but does not
 * flush caches.
 *
 * The caller is responsible for calling flush_cache_vmap() after this
 * function returns successfully and before the addresses are accessed.
 *
 * This is an internal function only. Do not use outside mm/.
 */
int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
                             pgprot_t prot, struct page **pages,
                             unsigned int page_shift)
{
    unsigned int i, nr = (end - addr) >> PAGE_SHIFT;

    WARN_ON(page_shift < PAGE_SHIFT);

    return vmap_small_pages_range_noflush(addr, end, prot, pages);
}

/**
 * vmap_pages_range - map pages to a kernel virtual address
 * @addr: start of the VM area to map
 * @end: end of the VM area to map (non-inclusive)
 * @prot: page protection flags to use
 * @pages: pages to map (always PAGE_SIZE pages)
 * @page_shift: maximum shift that the pages may be mapped with, @pages must
 * be aligned and contiguous up to at least this shift.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int vmap_pages_range(unsigned long addr, unsigned long end,
                            pgprot_t prot, struct page **pages,
                            unsigned int page_shift)
{
    int err;

    err = vmap_pages_range_noflush(addr, end, prot, pages, page_shift);
    return err;
}

static void *
__vmalloc_area_node(struct vm_struct *area, gfp_t gfp_mask,
                    pgprot_t prot, unsigned int page_shift, int node)
{
    const gfp_t nested_gfp = (gfp_mask & GFP_RECLAIM_MASK) | __GFP_ZERO;
    bool nofail = gfp_mask & __GFP_NOFAIL;
    unsigned long addr = (unsigned long)area->addr;
    unsigned long size = get_vm_area_size(area);
    unsigned long array_size;
    unsigned int nr_small_pages = size >> PAGE_SHIFT;
    unsigned int page_order;
    unsigned int flags;
    int ret;

    array_size = (unsigned long)nr_small_pages * sizeof(struct page *);
    gfp_mask |= __GFP_NOWARN;
    if (!(gfp_mask & (GFP_DMA | GFP_DMA32)))
        gfp_mask |= __GFP_HIGHMEM;

    /* Please note that the recursion is strictly bounded. */
    if (array_size > PAGE_SIZE) {
        area->pages = __vmalloc_node(array_size, 1, nested_gfp,
                                     node, area->caller);
    } else {
        area->pages = kmalloc_node(array_size, nested_gfp, node);
    }

    if (!area->pages) {
        warn_alloc(gfp_mask, NULL, "vmalloc error: size %lu, "
                   "failed to allocated page array size %lu",
                   nr_small_pages * PAGE_SIZE, array_size);
        free_vm_area(area);
        return NULL;
    }

    set_vm_area_page_order(area, page_shift - PAGE_SHIFT);
    page_order = vm_area_page_order(area);

    area->nr_pages = vm_area_alloc_pages(gfp_mask | __GFP_NOWARN,
                                         node, page_order,
                                         nr_small_pages, area->pages);

    atomic_long_add(area->nr_pages, &nr_vmalloc_pages);

    /*
     * If not enough pages were obtained to accomplish an
     * allocation request, free them via __vfree() if any.
     */
    if (area->nr_pages != nr_small_pages) {
        warn_alloc(gfp_mask, NULL, "vmalloc error: size %lu, "
                   "page order %u, failed to allocate pages",
                   area->nr_pages * PAGE_SIZE, page_order);
        goto fail;
    }

    /*
     * page tables allocations ignore external gfp mask, enforce it
     * by the scope API
     */
    if ((gfp_mask & (__GFP_FS | __GFP_IO)) == __GFP_IO)
        flags = memalloc_nofs_save();
    else if ((gfp_mask & (__GFP_FS | __GFP_IO)) == 0)
        flags = memalloc_noio_save();

    do {
        ret = vmap_pages_range(addr, addr + size, prot,
                               area->pages, page_shift);
        if (nofail && (ret < 0))
            schedule_timeout_uninterruptible(1);
    } while (nofail && (ret < 0));

    if ((gfp_mask & (__GFP_FS | __GFP_IO)) == __GFP_IO)
        memalloc_nofs_restore(flags);
    else if ((gfp_mask & (__GFP_FS | __GFP_IO)) == 0)
        memalloc_noio_restore(flags);

    if (ret < 0) {
        warn_alloc(gfp_mask, NULL,
                   "vmalloc error: size %lu, failed to map pages",
                   area->nr_pages * PAGE_SIZE);
        goto fail;
    }

    return area->addr;

 fail:
    __vfree(area->addr);
    return NULL;
}

/**
 * __vmalloc_node_range - allocate virtually contiguous memory
 * @size:         allocation size
 * @align:        desired alignment
 * @start:        vm area range start
 * @end:          vm area range end
 * @gfp_mask:         flags for the page level allocator
 * @prot:         protection mask for the allocated pages
 * @vm_flags:         additional vm area flags (e.g. %VM_NO_GUARD)
 * @node:         node to use for allocation or NUMA_NO_NODE
 * @caller:       caller's return address
 *
 * Allocate enough pages to cover @size from the page level
 * allocator with @gfp_mask flags. Please note that the full set of gfp
 * flags are not supported. GFP_KERNEL, GFP_NOFS and GFP_NOIO are all
 * supported.
 * Zone modifiers are not supported. From the reclaim modifiers
 * __GFP_DIRECT_RECLAIM is required (aka GFP_NOWAIT is not supported)
 * and only __GFP_NOFAIL is supported (i.e. __GFP_NORETRY and
 * __GFP_RETRY_MAYFAIL are not supported).
 *
 * __GFP_NOWARN can be used to suppress failures messages.
 *
 * Map them into contiguous kernel virtual space, using a pagetable
 * protection of @prot.
 *
 * Return: the address of the area or %NULL on failure
 */
void *
__vmalloc_node_range(unsigned long size, unsigned long align,
                     unsigned long start, unsigned long end, gfp_t gfp_mask,
                     pgprot_t prot, unsigned long vm_flags, int node,
                     const void *caller)
{
    struct vm_struct *area;
    void *ret;
    unsigned long real_size = size;
    unsigned long real_align = align;
    unsigned int shift = PAGE_SHIFT;

    if (WARN_ON_ONCE(!size))
        return NULL;

    if ((size >> PAGE_SHIFT) > totalram_pages()) {
        warn_alloc(gfp_mask, NULL,
                   "vmalloc error: size %lu, exceeds total pages", real_size);
        return NULL;
    }

 again:
    area = __get_vm_area_node(real_size, align, shift,
                              VM_ALLOC | VM_UNINITIALIZED | vm_flags,
                              start, end, node, gfp_mask, caller);
    if (!area) {
        bool nofail = gfp_mask & __GFP_NOFAIL;
        warn_alloc(gfp_mask, NULL,
                   "vmalloc error: size %lu, vm_struct allocation failed%s",
                   real_size, (nofail) ? ". Retrying." : "");
        if (nofail) {
            //schedule_timeout_uninterruptible(1);
            goto again;
        }
        goto fail;
    }

    /* Allocate physical pages and map them into vmalloc space. */
    ret = __vmalloc_area_node(area, gfp_mask, prot, shift, node);
    if (!ret)
        goto fail;

    /*
     * In this function, newly allocated vm_struct has VM_UNINITIALIZED
     * flag. It means that vm_struct is not fully initialized.
     * Now, it is fully initialized, so remove this flag here.
     */
    clear_vm_uninitialized_flag(area);

    return area->addr;

 fail:
    if (shift > PAGE_SHIFT) {
        shift = PAGE_SHIFT;
        align = real_align;
        size = real_size;
        goto again;
    }

    return NULL;
}

/**
 * __vmalloc_node - allocate virtually contiguous memory
 * @size:       allocation size
 * @align:      desired alignment
 * @gfp_mask:       flags for the page level allocator
 * @node:       node to use for allocation or NUMA_NO_NODE
 * @caller:     caller's return address
 *
 * Allocate enough pages to cover @size from the page level allocator with
 * @gfp_mask flags.  Map them into contiguous kernel virtual space.
 *
 * Reclaim modifiers in @gfp_mask - __GFP_NORETRY, __GFP_RETRY_MAYFAIL
 * and __GFP_NOFAIL are not supported
 *
 * Any use of gfp flags outside of GFP_KERNEL should be consulted
 * with mm people.
 *
 * Return: pointer to the allocated memory or %NULL on error
 */
void *__vmalloc_node(unsigned long size, unsigned long align,
                     gfp_t gfp_mask, int node, const void *caller)
{
    return __vmalloc_node_range(size, align, VMALLOC_START, VMALLOC_END,
                                gfp_mask, PAGE_KERNEL, 0, node, caller);
}

struct vm_struct *
get_vm_area_caller(unsigned long size, unsigned long flags, const void *caller)
{
    return __get_vm_area_node(size, 1, PAGE_SHIFT, flags,
                              VMALLOC_START, VMALLOC_END,
                              NUMA_NO_NODE, GFP_KERNEL, caller);
}

static int vmap_try_huge_pmd(pmd_t *pmd, unsigned long addr, unsigned long end,
                             phys_addr_t phys_addr, pgprot_t prot,
                             unsigned int max_page_shift)
{
    if (max_page_shift < PMD_SHIFT)
        return 0;

    if (!arch_vmap_pmd_supported(prot))
        return 0;

    if ((end - addr) != PMD_SIZE)
        return 0;

    if (!IS_ALIGNED(addr, PMD_SIZE))
        return 0;

    if (!IS_ALIGNED(phys_addr, PMD_SIZE))
        return 0;

    if (pmd_present(*pmd) && !pmd_free_pte_page(pmd, addr))
        return 0;

    return pmd_set_huge(pmd, phys_addr, prot);
}

static int vmap_try_huge_pud(pud_t *pud, unsigned long addr, unsigned long end,
                             phys_addr_t phys_addr, pgprot_t prot,
                             unsigned int max_page_shift)
{
    if (max_page_shift < PUD_SHIFT)
        return 0;

    if (!arch_vmap_pud_supported(prot))
        return 0;

    if ((end - addr) != PUD_SIZE)
        return 0;

    if (!IS_ALIGNED(addr, PUD_SIZE))
        return 0;

    if (!IS_ALIGNED(phys_addr, PUD_SIZE))
        return 0;

    if (pud_present(*pud) && !pud_free_pmd_page(pud, addr))
        return 0;

    return pud_set_huge(pud, phys_addr, prot);
}

static int vmap_try_huge_p4d(p4d_t *p4d, unsigned long addr, unsigned long end,
                             phys_addr_t phys_addr, pgprot_t prot,
                             unsigned int max_page_shift)
{
    if (max_page_shift < P4D_SHIFT)
        return 0;

    if (!arch_vmap_p4d_supported(prot))
        return 0;

    if ((end - addr) != P4D_SIZE)
        return 0;

    if (!IS_ALIGNED(addr, P4D_SIZE))
        return 0;

    if (!IS_ALIGNED(phys_addr, P4D_SIZE))
        return 0;

    if (p4d_present(*p4d) && !p4d_free_pud_page(p4d, addr))
        return 0;

    return p4d_set_huge(p4d, phys_addr, prot);
}

/*** Page table manipulation functions ***/
static int vmap_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
            phys_addr_t phys_addr, pgprot_t prot,
            unsigned int max_page_shift, pgtbl_mod_mask *mask)
{
    pte_t *pte;
    u64 pfn;
    unsigned long size = PAGE_SIZE;

    pfn = phys_addr >> PAGE_SHIFT;
    pte = pte_alloc_kernel_track(pmd, addr, mask);
    if (!pte)
        return -ENOMEM;
    do {
        BUG_ON(!pte_none(*pte));

        size = arch_vmap_pte_range_map_size(addr, end, pfn, max_page_shift);
        if (size != PAGE_SIZE) {
            pte_t entry = pfn_pte(pfn, prot);

            entry = arch_make_huge_pte(entry, ilog2(size), 0);
            set_huge_pte_at(&init_mm, addr, pte, entry);
            pfn += PFN_DOWN(size);
            continue;
        }
        set_pte_at(&init_mm, addr, pte, pfn_pte(pfn, prot));
        pfn++;
    } while (pte += PFN_DOWN(size), addr += size, addr != end);
    *mask |= PGTBL_PTE_MODIFIED;
    return 0;
}

static int vmap_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
                          phys_addr_t phys_addr, pgprot_t prot,
                          unsigned int max_page_shift, pgtbl_mod_mask *mask)
{
    pmd_t *pmd;
    unsigned long next;

    pmd = pmd_alloc_track(&init_mm, pud, addr, mask);
    if (!pmd)
        return -ENOMEM;
    do {
        next = pmd_addr_end(addr, end);

        if (vmap_try_huge_pmd(pmd, addr, next, phys_addr, prot,
                              max_page_shift)) {
            *mask |= PGTBL_PMD_MODIFIED;
            continue;
        }

        if (vmap_pte_range(pmd, addr, next, phys_addr, prot,
                           max_page_shift, mask))
            return -ENOMEM;
    } while (pmd++, phys_addr += (next - addr), addr = next, addr != end);
    return 0;
}

static int vmap_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end,
                          phys_addr_t phys_addr, pgprot_t prot,
                          unsigned int max_page_shift, pgtbl_mod_mask *mask)
{
    pud_t *pud;
    unsigned long next;

    pud = pud_alloc_track(&init_mm, p4d, addr, mask);
    if (!pud)
        return -ENOMEM;
    do {
        next = pud_addr_end(addr, end);

        if (vmap_try_huge_pud(pud, addr, next, phys_addr, prot,
                              max_page_shift)) {
            *mask |= PGTBL_PUD_MODIFIED;
            continue;
        }

        if (vmap_pmd_range(pud, addr, next, phys_addr, prot,
                           max_page_shift, mask))
            return -ENOMEM;
    } while (pud++, phys_addr += (next - addr), addr = next, addr != end);
    return 0;
}

static int vmap_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
                          phys_addr_t phys_addr, pgprot_t prot,
                          unsigned int max_page_shift, pgtbl_mod_mask *mask)
{
    p4d_t *p4d;
    unsigned long next;

    p4d = p4d_alloc_track(&init_mm, pgd, addr, mask);
    if (!p4d)
        return -ENOMEM;
    do {
        next = p4d_addr_end(addr, end);

        if (vmap_try_huge_p4d(p4d, addr, next, phys_addr, prot,
                              max_page_shift)) {
            *mask |= PGTBL_P4D_MODIFIED;
            continue;
        }

        if (vmap_pud_range(p4d, addr, next, phys_addr, prot,
                           max_page_shift, mask))
            return -ENOMEM;
    } while (p4d++, phys_addr += (next - addr), addr = next, addr != end);
    return 0;
}

static int vmap_range_noflush(unsigned long addr, unsigned long end,
                              phys_addr_t phys_addr, pgprot_t prot,
                              unsigned int max_page_shift)
{
    pgd_t *pgd;
    unsigned long start;
    unsigned long next;
    int err;
    pgtbl_mod_mask mask = 0;

    might_sleep();
    BUG_ON(addr >= end);

    start = addr;
    pgd = pgd_offset_k(addr);
    do {
        next = pgd_addr_end(addr, end);
        err = vmap_p4d_range(pgd, addr, next, phys_addr, prot, max_page_shift,
                             &mask);
        if (err)
            break;
    } while (pgd++, phys_addr += (next - addr), addr = next, addr != end);

    return err;
}

int ioremap_page_range(unsigned long addr, unsigned long end,
                       phys_addr_t phys_addr, pgprot_t prot)
{
    int err;

    err = vmap_range_noflush(addr, end, phys_addr, pgprot_nx(prot),
                             ioremap_max_page_shift);
    return err;
}

void __init vmalloc_init(void)
{
    int i;
    struct vmap_area *va;
    struct vm_struct *tmp;

    /*
     * Create the cache for vmap_area objects.
     */
    vmap_area_cachep = KMEM_CACHE(vmap_area, SLAB_PANIC);

#if 0
    for_each_possible_cpu(i) {
        struct vmap_block_queue *vbq;
        struct vfree_deferred *p;

        vbq = &per_cpu(vmap_block_queue, i);
        spin_lock_init(&vbq->lock);
        INIT_LIST_HEAD(&vbq->free);
        p = &per_cpu(vfree_deferred, i);
        init_llist_head(&p->list);
        INIT_WORK(&p->wq, free_work);
    }
#endif

    /* Import existing vmlist entries. */
    for (tmp = vmlist; tmp; tmp = tmp->next) {
        va = kmem_cache_zalloc(vmap_area_cachep, GFP_NOWAIT);
        if (WARN_ON_ONCE(!va))
            continue;

        va->va_start = (unsigned long)tmp->addr;
        va->va_end = va->va_start + tmp->size;
        va->vm = tmp;
        insert_vmap_area(va, &vmap_area_root, &vmap_area_list);
    }

    /*
     * Now we can initialize a free vmap space.
     */
    vmap_init_free_space();
    vmap_initialized = true;
}

bool is_vmalloc_addr(const void *x)
{
    unsigned long addr = (unsigned long)(x);

    return addr >= VMALLOC_START && addr < VMALLOC_END;
}
EXPORT_SYMBOL(is_vmalloc_addr);

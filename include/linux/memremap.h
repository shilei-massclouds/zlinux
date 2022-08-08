/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MEMREMAP_H_
#define _LINUX_MEMREMAP_H_

#include <linux/range.h>
#include <linux/ioport.h>
#include <linux/percpu-refcount.h>

/**
 * struct vmem_altmap - pre-allocated storage for vmemmap_populate
 * @base_pfn: base of the entire dev_pagemap mapping
 * @reserve: pages mapped, but reserved for driver use (relative to @base)
 * @free: free pages set aside in the mapping for memmap storage
 * @align: pages reserved to meet allocation alignments
 * @alloc: track pages consumed, private to vmemmap_populate()
 */
struct vmem_altmap {
    unsigned long base_pfn;
    const unsigned long end_pfn;
    const unsigned long reserve;
    unsigned long free;
    unsigned long align;
    unsigned long alloc;
};

/*
 * Specialize ZONE_DEVICE memory into multiple types each has a different
 * usage.
 *
 * MEMORY_DEVICE_PRIVATE:
 * Device memory that is not directly addressable by the CPU: CPU can neither
 * read nor write private memory. In this case, we do still have struct pages
 * backing the device memory. Doing so simplifies the implementation, but it is
 * important to remember that there are certain points at which the struct page
 * must be treated as an opaque object, rather than a "normal" struct page.
 *
 * A more complete discussion of unaddressable memory may be found in
 * include/linux/hmm.h and Documentation/vm/hmm.rst.
 *
 * MEMORY_DEVICE_FS_DAX:
 * Host memory that has similar access semantics as System RAM i.e. DMA
 * coherent and supports page pinning. In support of coordinating page
 * pinning vs other operations MEMORY_DEVICE_FS_DAX arranges for a
 * wakeup event whenever a page is unpinned and becomes idle. This
 * wakeup is used to coordinate physical address space management (ex:
 * fs truncate/hole punch) vs pinned pages (ex: device dma).
 *
 * MEMORY_DEVICE_GENERIC:
 * Host memory that has similar access semantics as System RAM i.e. DMA
 * coherent and supports page pinning. This is for example used by DAX devices
 * that expose memory using a character device.
 *
 * MEMORY_DEVICE_PCI_P2PDMA:
 * Device memory residing in a PCI BAR intended for use with Peer-to-Peer
 * transactions.
 */
enum memory_type {
    /* 0 is reserved to catch uninitialized type fields */
    MEMORY_DEVICE_PRIVATE = 1,
    MEMORY_DEVICE_FS_DAX,
    MEMORY_DEVICE_GENERIC,
    MEMORY_DEVICE_PCI_P2PDMA,
};

/**
 * struct dev_pagemap - metadata for ZONE_DEVICE mappings
 * @altmap: pre-allocated/reserved memory for vmemmap allocations
 * @ref: reference count that pins the devm_memremap_pages() mapping
 * @done: completion for @ref
 * @type: memory type: see MEMORY_* in memory_hotplug.h
 * @flags: PGMAP_* flags to specify defailed behavior
 * @vmemmap_shift: structural definition of how the vmemmap page metadata
 *      is populated, specifically the metadata page order.
 *  A zero value (default) uses base pages as the vmemmap metadata
 *  representation. A bigger value will set up compound struct pages
 *  of the requested order value.
 * @ops: method table
 * @owner: an opaque pointer identifying the entity that manages this
 *  instance.  Used by various helpers to make sure that no
 *  foreign ZONE_DEVICE memory is accessed.
 * @nr_range: number of ranges to be mapped
 * @range: range to be mapped when nr_range == 1
 * @ranges: array of ranges to be mapped when nr_range > 1
 */
struct dev_pagemap {
    struct vmem_altmap altmap;
    struct percpu_ref ref;
    struct completion done;
    enum memory_type type;
    unsigned int flags;
    unsigned long vmemmap_shift;
    const struct dev_pagemap_ops *ops;
    void *owner;
    int nr_range;
    union {
        struct range range;
        struct range ranges[0];
    };
};

static inline void put_dev_pagemap(struct dev_pagemap *pgmap)
{
    if (pgmap)
        percpu_ref_put(&pgmap->ref);
}

#endif /* _LINUX_MEMREMAP_H_ */

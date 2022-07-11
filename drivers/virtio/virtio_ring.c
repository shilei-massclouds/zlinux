// SPDX-License-Identifier: GPL-2.0-or-later
/* Virtio ring implementation.
 *
 *  Copyright 2007 Rusty Russell IBM Corporation
 */
#include <linux/virtio.h>
#include <linux/virtio_ring.h>
#include <linux/virtio_config.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/module.h>
#if 0
#include <linux/hrtimer.h>
#endif
#include <linux/dma-mapping.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/io.h>

struct vring_virtqueue {
    struct virtqueue vq;

    /* Is DMA API used? */
    bool use_dma_api;

    /* Can we use weak barriers? */
    bool weak_barriers;

    /* Other side has made a mess, don't try any more. */
    bool broken;

    /* Host supports indirect buffers */
    bool indirect;

    /* Host publishes avail event idx */
    bool event;

    /* Head of free buffer list. */
    unsigned int free_head;
    /* Number we've added since last sync. */
    unsigned int num_added;

    /* Last used index we've seen. */
    u16 last_used_idx;

    /* Hint for event idx: already triggered no need to disable. */
    bool event_triggered;

    /* Available for split ring */
    struct {
        /* Actual memory layout for this queue. */
        struct vring vring;

        /* Last written value to avail->flags */
        u16 avail_flags_shadow;

        /*
         * Last written value to avail->idx in
         * guest byte order.
         */
        u16 avail_idx_shadow;

        /* Per-descriptor state. */
        struct vring_desc_state_split *desc_state;
        struct vring_desc_extra *desc_extra;

        /* DMA address and size information */
        dma_addr_t queue_dma_addr;
        size_t queue_size_in_bytes;
    } split;

    /* How to notify other side. FIXME: commonalize hcalls! */
    bool (*notify)(struct virtqueue *vq);

    /* DMA, allocation, and size information */
    bool we_own_ring;
};

struct vring_desc_state_split {
    void *data;                     /* Data for callback. */
    struct vring_desc *indir_desc;  /* Indirect descriptor, if any. */
};

struct vring_desc_extra {
    dma_addr_t addr;    /* Descriptor DMA addr. */
    u32 len;            /* Descriptor length. */
    u16 flags;          /* Descriptor flags. */
    u16 next;           /* The next desc state in a list. */
};

/*
 * Helpers.
 */

#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

/* Manipulates transport-specific feature bits. */
void vring_transport_features(struct virtio_device *vdev)
{
    unsigned int i;

    for (i = VIRTIO_TRANSPORT_F_START; i < VIRTIO_TRANSPORT_F_END; i++) {
        switch (i) {
        case VIRTIO_RING_F_INDIRECT_DESC:
            break;
        case VIRTIO_RING_F_EVENT_IDX:
            break;
        case VIRTIO_F_VERSION_1:
            break;
        case VIRTIO_F_ACCESS_PLATFORM:
            break;
        case VIRTIO_F_RING_PACKED:
            break;
        case VIRTIO_F_ORDER_PLATFORM:
            break;
        default:
            /* We don't understand this bit. */
            __virtio_clear_bit(vdev, i);
        }
    }
}
EXPORT_SYMBOL_GPL(vring_transport_features);

void vring_del_virtqueue(struct virtqueue *_vq)
{
    panic("%s: END!\n", __func__);
}
EXPORT_SYMBOL_GPL(vring_del_virtqueue);

/*
 * Modern virtio devices have feature bits to specify whether they need a
 * quirk and bypass the IOMMU. If not there, just use the DMA API.
 *
 * If there, the interaction between virtio and DMA API is messy.
 *
 * On most systems with virtio, physical addresses match bus addresses,
 * and it doesn't particularly matter whether we use the DMA API.
 *
 * On some systems, including Xen and any system with a physical device
 * that speaks virtio behind a physical IOMMU, we must use the DMA API
 * for virtio DMA to work at all.
 *
 * On other systems, including SPARC and PPC64, virtio-pci devices are
 * enumerated as though they are behind an IOMMU, but the virtio host
 * ignores the IOMMU, so we must either pretend that the IOMMU isn't
 * there or somehow map everything as the identity.
 *
 * For the time being, we preserve historic behavior and bypass the DMA
 * API.
 *
 * TODO: install a per-device DMA ops structure that does the right thing
 * taking into account all the above quirks, and use the DMA API
 * unconditionally on data path.
 */

static bool vring_use_dma_api(struct virtio_device *vdev)
{
    if (!virtio_has_dma_quirk(vdev))
        return true;

    /* Otherwise, we are left to guess. */

    return false;
}

static void *vring_alloc_queue(struct virtio_device *vdev, size_t size,
                               dma_addr_t *dma_handle, gfp_t flag)
{
    if (vring_use_dma_api(vdev)) {
        panic("%s: NO DMA API!\n", __func__);
    } else {
        void *queue = alloc_pages_exact(PAGE_ALIGN(size), flag);

        if (queue) {
            phys_addr_t phys_addr = virt_to_phys(queue);
            *dma_handle = (dma_addr_t)phys_addr;

            /*
             * Sanity check: make sure we dind't truncate
             * the address.  The only arches I can find that
             * have 64-bit phys_addr_t but 32-bit dma_addr_t
             * are certain non-highmem MIPS and x86
             * configurations, but these configurations
             * should never allocate physical pages above 32
             * bits, so this is fine.  Just in case, throw a
             * warning and abort if we end up with an
             * unrepresentable address.
             */
            if (WARN_ON_ONCE(*dma_handle != phys_addr)) {
                free_pages_exact(queue, PAGE_ALIGN(size));
                return NULL;
            }
        }
        return queue;
    }
}

static struct virtqueue *
vring_create_virtqueue_packed(unsigned int index,
                              unsigned int num,
                              unsigned int vring_align,
                              struct virtio_device *vdev,
                              bool weak_barriers,
                              bool may_reduce_num,
                              bool context,
                              bool (*notify)(struct virtqueue *),
                              void (*callback)(struct virtqueue *),
                              const char *name)
{
    panic("%s: END!\n", __func__);
}

static struct vring_desc_extra *
vring_alloc_desc_extra(struct vring_virtqueue *vq, unsigned int num)
{
    struct vring_desc_extra *desc_extra;
    unsigned int i;

    desc_extra = kmalloc_array(num, sizeof(struct vring_desc_extra),
                               GFP_KERNEL);
    if (!desc_extra)
        return NULL;

    memset(desc_extra, 0, num * sizeof(struct vring_desc_extra));

    for (i = 0; i < num - 1; i++)
        desc_extra[i].next = i + 1;

    return desc_extra;
}

/* Only available for split ring */
struct virtqueue *
__vring_new_virtqueue(unsigned int index,
                      struct vring vring,
                      struct virtio_device *vdev,
                      bool weak_barriers,
                      bool context,
                      bool (*notify)(struct virtqueue *),
                      void (*callback)(struct virtqueue *),
                      const char *name)
{
    struct vring_virtqueue *vq;

    if (virtio_has_feature(vdev, VIRTIO_F_RING_PACKED))
        return NULL;

    vq = kmalloc(sizeof(*vq), GFP_KERNEL);
    if (!vq)
        return NULL;

    vq->vq.callback = callback;
    vq->vq.vdev = vdev;
    vq->vq.name = name;
    vq->vq.num_free = vring.num;
    vq->vq.index = index;
    vq->we_own_ring = false;
    vq->notify = notify;
    vq->weak_barriers = weak_barriers;
    vq->broken = false;
    vq->last_used_idx = 0;
    vq->event_triggered = false;
    vq->num_added = 0;
    vq->use_dma_api = vring_use_dma_api(vdev);

    vq->indirect = virtio_has_feature(vdev, VIRTIO_RING_F_INDIRECT_DESC) &&
        !context;
    vq->event = virtio_has_feature(vdev, VIRTIO_RING_F_EVENT_IDX);

    if (virtio_has_feature(vdev, VIRTIO_F_ORDER_PLATFORM))
        vq->weak_barriers = false;

    vq->split.queue_dma_addr = 0;
    vq->split.queue_size_in_bytes = 0;

    vq->split.vring = vring;
    vq->split.avail_flags_shadow = 0;
    vq->split.avail_idx_shadow = 0;

    /* No callback?  Tell other side not to bother us. */
    if (!callback) {
        vq->split.avail_flags_shadow |= VRING_AVAIL_F_NO_INTERRUPT;
        if (!vq->event)
            vq->split.vring.avail->flags =
                cpu_to_virtio16(vdev, vq->split.avail_flags_shadow);
    }

    vq->split.desc_state = kmalloc_array(vring.num,
                                         sizeof(struct vring_desc_state_split),
                                         GFP_KERNEL);
    if (!vq->split.desc_state)
        goto err_state;

    vq->split.desc_extra = vring_alloc_desc_extra(vq, vring.num);
    if (!vq->split.desc_extra)
        goto err_extra;

    /* Put everything in free lists. */
    vq->free_head = 0;
    memset(vq->split.desc_state, 0,
           vring.num * sizeof(struct vring_desc_state_split));

    spin_lock(&vdev->vqs_list_lock);
    list_add_tail(&vq->vq.list, &vdev->vqs);
    spin_unlock(&vdev->vqs_list_lock);
    return &vq->vq;

err_extra:
    kfree(vq->split.desc_state);
err_state:
    kfree(vq);
    return NULL;
}

static void vring_free_queue(struct virtio_device *vdev, size_t size,
                             void *queue, dma_addr_t dma_handle)
{
    if (vring_use_dma_api(vdev)) {
        panic("%s: USE DMA API!\n", __func__);
        //dma_free_coherent(vdev->dev.parent, size, queue, dma_handle);
    } else {
        free_pages_exact(queue, PAGE_ALIGN(size));
    }
}

static struct virtqueue *
vring_create_virtqueue_split(unsigned int index,
                             unsigned int num,
                             unsigned int vring_align,
                             struct virtio_device *vdev,
                             bool weak_barriers,
                             bool may_reduce_num,
                             bool context,
                             bool (*notify)(struct virtqueue *),
                             void (*callback)(struct virtqueue *),
                             const char *name)
{
    struct virtqueue *vq;
    void *queue = NULL;
    dma_addr_t dma_addr;
    size_t queue_size_in_bytes;
    struct vring vring;

    /* We assume num is a power of 2. */
    if (num & (num - 1)) {
        pr_warn("Bad virtqueue length %u\n", num);
        return NULL;
    }

    /* TODO: allocate each queue chunk individually */
    for (; num && vring_size(num, vring_align) > PAGE_SIZE; num /= 2) {
        queue = vring_alloc_queue(vdev, vring_size(num, vring_align),
                                  &dma_addr,
                                  GFP_KERNEL|__GFP_NOWARN|__GFP_ZERO);
        if (queue)
            break;
        if (!may_reduce_num)
            return NULL;
    }

    if (!num)
        return NULL;

    if (!queue) {
        /* Try to get a single page. You are my only hope! */
        queue = vring_alloc_queue(vdev, vring_size(num, vring_align),
                                  &dma_addr, GFP_KERNEL|__GFP_ZERO);
    }
    if (!queue)
        return NULL;

    queue_size_in_bytes = vring_size(num, vring_align);
    vring_init(&vring, num, queue, vring_align);

    vq = __vring_new_virtqueue(index, vring, vdev, weak_barriers, context,
                               notify, callback, name);
    if (!vq) {
        vring_free_queue(vdev, queue_size_in_bytes, queue, dma_addr);
        return NULL;
    }

    to_vvq(vq)->split.queue_dma_addr = dma_addr;
    to_vvq(vq)->split.queue_size_in_bytes = queue_size_in_bytes;
    to_vvq(vq)->we_own_ring = true;

    return vq;
}

struct virtqueue *vring_create_virtqueue(
    unsigned int index,
    unsigned int num,
    unsigned int vring_align,
    struct virtio_device *vdev,
    bool weak_barriers,
    bool may_reduce_num,
    bool context,
    bool (*notify)(struct virtqueue *),
    void (*callback)(struct virtqueue *),
    const char *name)
{

    if (virtio_has_feature(vdev, VIRTIO_F_RING_PACKED))
        return vring_create_virtqueue_packed(index, num, vring_align,
                                             vdev, weak_barriers,
                                             may_reduce_num, context,
                                             notify, callback, name);

    return vring_create_virtqueue_split(index, num, vring_align,
                                        vdev, weak_barriers,
                                        may_reduce_num, context,
                                        notify, callback, name);
}
EXPORT_SYMBOL_GPL(vring_create_virtqueue);

/**
 * virtqueue_get_vring_size - return the size of the virtqueue's vring
 * @_vq: the struct virtqueue containing the vring of interest.
 *
 * Returns the size of the vring.  This is mainly used for boasting to
 * userspace.  Unlike other operations, this need not be serialized.
 */
unsigned int virtqueue_get_vring_size(struct virtqueue *_vq)
{

    struct vring_virtqueue *vq = to_vvq(_vq);

    return vq->split.vring.num;
}
EXPORT_SYMBOL_GPL(virtqueue_get_vring_size);

dma_addr_t virtqueue_get_desc_addr(struct virtqueue *_vq)
{
    struct vring_virtqueue *vq = to_vvq(_vq);

    BUG_ON(!vq->we_own_ring);

    return vq->split.queue_dma_addr;
}
EXPORT_SYMBOL_GPL(virtqueue_get_desc_addr);

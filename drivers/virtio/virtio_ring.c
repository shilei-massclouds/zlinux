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

#define BAD_RING(_vq, fmt, args...) \
    do {                            \
        dev_err(&_vq->vq.vdev->dev, \
            "%s:"fmt, (_vq)->vq.name, ##args);  \
        (_vq)->broken = true;       \
    } while (0)

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

size_t virtio_max_dma_size(struct virtio_device *vdev)
{
    size_t max_segment_size = SIZE_MAX;

    if (vring_use_dma_api(vdev)) {
        panic("%s: USE DMA API!\n", __func__);
        //max_segment_size = dma_max_mapping_size(vdev->dev.parent);
    }

    return max_segment_size;
}
EXPORT_SYMBOL_GPL(virtio_max_dma_size);

#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

static inline bool virtqueue_use_indirect(struct virtqueue *_vq,
                                          unsigned int total_sg)
{
    struct vring_virtqueue *vq = to_vvq(_vq);

    /*
     * If the host supports indirect descriptor tables, and we have multiple
     * buffers, then go indirect. FIXME: tune this threshold
     */
    return (vq->indirect && total_sg > 1 && vq->vq.num_free);
}

static struct vring_desc *
alloc_indirect_split(struct virtqueue *_vq, unsigned int total_sg, gfp_t gfp)
{
    struct vring_desc *desc;
    unsigned int i;

    /*
     * We require lowmem mappings for the descriptors because
     * otherwise virt_to_phys will give us bogus addresses in the
     * virtqueue.
     */
    gfp &= ~__GFP_HIGHMEM;

    desc = kmalloc_array(total_sg, sizeof(struct vring_desc), gfp);
    if (!desc)
        return NULL;

    for (i = 0; i < total_sg; i++)
        desc[i].next = cpu_to_virtio16(_vq->vdev, i + 1);
    return desc;
}

/*
 * The DMA ops on various arches are rather gnarly right now, and
 * making all of the arch DMA ops work on the vring device itself
 * is a mess.  For now, we use the parent device for DMA ops.
 */
static inline struct device *vring_dma_dev(const struct vring_virtqueue *vq)
{
    return vq->vq.vdev->dev.parent;
}

/*
 * Split ring specific functions - *_split().
 */

static void vring_unmap_one_split_indirect(const struct vring_virtqueue *vq,
                                           struct vring_desc *desc)
{
    u16 flags;

    if (!vq->use_dma_api)
        return;

#if 0
    flags = virtio16_to_cpu(vq->vq.vdev, desc->flags);

    dma_unmap_page(vring_dma_dev(vq),
                   virtio64_to_cpu(vq->vq.vdev, desc->addr),
                   virtio32_to_cpu(vq->vq.vdev, desc->len),
                   (flags & VRING_DESC_F_WRITE) ?
                   DMA_FROM_DEVICE : DMA_TO_DEVICE);
#endif
    panic("%s: END!\n", __func__);
}

static unsigned int
vring_unmap_one_split(const struct vring_virtqueue *vq, unsigned int i)
{
    struct vring_desc_extra *extra = vq->split.desc_extra;
    u16 flags;

    if (!vq->use_dma_api)
        goto out;

    flags = extra[i].flags;

#if 0
    if (flags & VRING_DESC_F_INDIRECT) {
        dma_unmap_single(vring_dma_dev(vq),
                         extra[i].addr,
                         extra[i].len,
                         (flags & VRING_DESC_F_WRITE) ?
                         DMA_FROM_DEVICE : DMA_TO_DEVICE);
    } else {
        dma_unmap_page(vring_dma_dev(vq),
                       extra[i].addr,
                       extra[i].len,
                       (flags & VRING_DESC_F_WRITE) ?
                       DMA_FROM_DEVICE : DMA_TO_DEVICE);
    }
#endif
    panic("%s: END!\n", __func__);

out:
    return extra[i].next;
}

static int vring_mapping_error(const struct vring_virtqueue *vq,
                               dma_addr_t addr)
{
    if (!vq->use_dma_api)
        return 0;

#if 0
    return dma_mapping_error(vring_dma_dev(vq), addr);
#endif
    panic("%s: END!\n", __func__);
}

static inline unsigned int
virtqueue_add_desc_split(struct virtqueue *vq,
                         struct vring_desc *desc,
                         unsigned int i,
                         dma_addr_t addr,
                         unsigned int len,
                         u16 flags,
                         bool indirect)
{
    struct vring_virtqueue *vring = to_vvq(vq);
    struct vring_desc_extra *extra = vring->split.desc_extra;
    u16 next;

    desc[i].flags = cpu_to_virtio16(vq->vdev, flags);
    desc[i].addr = cpu_to_virtio64(vq->vdev, addr);
    desc[i].len = cpu_to_virtio32(vq->vdev, len);

    if (!indirect) {
        next = extra[i].next;
        desc[i].next = cpu_to_virtio16(vq->vdev, next);

        extra[i].addr = addr;
        extra[i].len = len;
        extra[i].flags = flags;
    } else
        next = virtio16_to_cpu(vq->vdev, desc[i].next);

    return next;
}

/* Map one sg entry. */
static dma_addr_t vring_map_one_sg(const struct vring_virtqueue *vq,
                                   struct scatterlist *sg,
                                   enum dma_data_direction direction)
{
    if (!vq->use_dma_api)
        return (dma_addr_t)sg_phys(sg);

#if 0
    /*
     * We can't use dma_map_sg, because we don't use scatterlists in
     * the way it expects (we don't guarantee that the scatterlist
     * will exist for the lifetime of the mapping).
     */
    return dma_map_page(vring_dma_dev(vq),
                        sg_page(sg), sg->offset, sg->length,
                        direction);
#endif
    panic("%s: END!\n", __func__);
}

static dma_addr_t vring_map_single(const struct vring_virtqueue *vq,
                                   void *cpu_addr, size_t size,
                                   enum dma_data_direction direction)
{
    if (!vq->use_dma_api)
        return (dma_addr_t)virt_to_phys(cpu_addr);

#if 0
    return dma_map_single(vring_dma_dev(vq), cpu_addr, size, direction);
#endif
    panic("%s: END!\n", __func__);
}

static bool virtqueue_kick_prepare_split(struct virtqueue *_vq)
{
    struct vring_virtqueue *vq = to_vvq(_vq);
    u16 new, old;
    bool needs_kick;

    /* We need to expose available array entries before checking avail
     * event. */
    virtio_mb(vq->weak_barriers);

    old = vq->split.avail_idx_shadow - vq->num_added;
    new = vq->split.avail_idx_shadow;
    vq->num_added = 0;

    if (vq->event) {
        needs_kick = vring_need_event(
                        virtio16_to_cpu(_vq->vdev,
                                        vring_avail_event(&vq->split.vring)),
                                        new, old);
    } else {
        needs_kick = !(vq->split.vring.used->flags &
                       cpu_to_virtio16(_vq->vdev, VRING_USED_F_NO_NOTIFY));
    }
    return needs_kick;
}

/**
 * virtqueue_kick_prepare - first half of split virtqueue_kick call.
 * @_vq: the struct virtqueue
 *
 * Instead of virtqueue_kick(), you can do:
 *  if (virtqueue_kick_prepare(vq))
 *      virtqueue_notify(vq);
 *
 * This is sometimes useful because the virtqueue_kick_prepare() needs
 * to be serialized, but the actual virtqueue_notify() call does not.
 */
bool virtqueue_kick_prepare(struct virtqueue *_vq)
{
    struct vring_virtqueue *vq = to_vvq(_vq);

    return virtqueue_kick_prepare_split(_vq);
}
EXPORT_SYMBOL_GPL(virtqueue_kick_prepare);

/**
 * virtqueue_notify - second half of split virtqueue_kick call.
 * @_vq: the struct virtqueue
 *
 * This does not need to be serialized.
 *
 * Returns false if host notify failed or queue is broken, otherwise true.
 */
bool virtqueue_notify(struct virtqueue *_vq)
{
    struct vring_virtqueue *vq = to_vvq(_vq);

    if (unlikely(vq->broken))
        return false;

    /* Prod other side to tell it about changes. */
    if (!vq->notify(_vq)) {
        vq->broken = true;
        return false;
    }
    return true;
}
EXPORT_SYMBOL_GPL(virtqueue_notify);

/**
 * virtqueue_kick - update after add_buf
 * @vq: the struct virtqueue
 *
 * After one or more virtqueue_add_* calls, invoke this to kick
 * the other side.
 *
 * Caller must ensure we don't call this with other virtqueue
 * operations at the same time (except where noted).
 *
 * Returns false if kick failed, otherwise true.
 */
bool virtqueue_kick(struct virtqueue *vq)
{
    if (virtqueue_kick_prepare(vq))
        return virtqueue_notify(vq);
    return true;
}
EXPORT_SYMBOL_GPL(virtqueue_kick);

static inline
int virtqueue_add_split(struct virtqueue *_vq,
                        struct scatterlist *sgs[],
                        unsigned int total_sg,
                        unsigned int out_sgs,
                        unsigned int in_sgs,
                        void *data,
                        void *ctx,
                        gfp_t gfp)
{
    struct vring_virtqueue *vq = to_vvq(_vq);
    struct scatterlist *sg;
    struct vring_desc *desc;
    unsigned int i, n, avail, descs_used, prev, err_idx;
    int head;
    bool indirect;

    BUG_ON(data == NULL);
    BUG_ON(ctx && vq->indirect);

    if (unlikely(vq->broken)) {
        return -EIO;
    }

    BUG_ON(total_sg == 0);

    head = vq->free_head;

    if (virtqueue_use_indirect(_vq, total_sg))
        desc = alloc_indirect_split(_vq, total_sg, gfp);
    else {
        desc = NULL;
        WARN_ON_ONCE(total_sg > vq->split.vring.num && !vq->indirect);
    }

    if (desc) {
        /* Use a single buffer which doesn't continue */
        indirect = true;
        /* Set up rest to use this indirect table. */
        i = 0;
        descs_used = 1;
    } else {
        indirect = false;
        desc = vq->split.vring.desc;
        i = head;
        descs_used = total_sg;
    }

    if (vq->vq.num_free < descs_used) {
        pr_debug("Can't add buf len %i - avail = %i\n",
                 descs_used, vq->vq.num_free);
        /* FIXME: for historical reasons, we force a notify here if
         * there are outgoing parts to the buffer.  Presumably the
         * host should service the ring ASAP. */
        if (out_sgs)
            vq->notify(&vq->vq);
        if (indirect)
            kfree(desc);
        return -ENOSPC;
    }

    for (n = 0; n < out_sgs; n++) {
        for (sg = sgs[n]; sg; sg = sg_next(sg)) {
            dma_addr_t addr = vring_map_one_sg(vq, sg, DMA_TO_DEVICE);
            if (vring_mapping_error(vq, addr))
                goto unmap_release;

            prev = i;
            /* Note that we trust indirect descriptor
             * table since it use stream DMA mapping.
             */
            i = virtqueue_add_desc_split(_vq, desc, i, addr, sg->length,
                                         VRING_DESC_F_NEXT, indirect);
        }
    }
    for (; n < (out_sgs + in_sgs); n++) {
        for (sg = sgs[n]; sg; sg = sg_next(sg)) {
            dma_addr_t addr = vring_map_one_sg(vq, sg, DMA_FROM_DEVICE);
            if (vring_mapping_error(vq, addr))
                goto unmap_release;

            prev = i;
            /* Note that we trust indirect descriptor
             * table since it use stream DMA mapping.
             */
            i = virtqueue_add_desc_split(_vq, desc, i, addr, sg->length,
                                         VRING_DESC_F_NEXT | VRING_DESC_F_WRITE,
                                         indirect);
        }
    }
    /* Last one doesn't continue. */
    desc[prev].flags &= cpu_to_virtio16(_vq->vdev, ~VRING_DESC_F_NEXT);
    if (!indirect && vq->use_dma_api)
        vq->split.desc_extra[prev & (vq->split.vring.num - 1)].flags &=
            ~VRING_DESC_F_NEXT;

    if (indirect) {
        /* Now that the indirect table is filled in, map it. */
        dma_addr_t addr = vring_map_single(vq, desc,
                                           total_sg * sizeof(struct vring_desc),
                                           DMA_TO_DEVICE);
        if (vring_mapping_error(vq, addr))
            goto unmap_release;

        virtqueue_add_desc_split(_vq, vq->split.vring.desc, head, addr,
                                 total_sg * sizeof(struct vring_desc),
                                 VRING_DESC_F_INDIRECT,
                                 false);
    }

    /* We're using some buffers from the free list. */
    vq->vq.num_free -= descs_used;

    /* Update free pointer */
    if (indirect)
        vq->free_head = vq->split.desc_extra[head].next;
    else
        vq->free_head = i;

    /* Store token and indirect buffer state. */
    vq->split.desc_state[head].data = data;
    if (indirect)
        vq->split.desc_state[head].indir_desc = desc;
    else
        vq->split.desc_state[head].indir_desc = ctx;

    /* Put entry in available array (but don't update avail->idx until they
     * do sync). */
    avail = vq->split.avail_idx_shadow & (vq->split.vring.num - 1);
    vq->split.vring.avail->ring[avail] = cpu_to_virtio16(_vq->vdev, head);

    /* Descriptors and available array need to be set before we expose the
     * new available array entries. */
    virtio_wmb(vq->weak_barriers);
    vq->split.avail_idx_shadow++;
    vq->split.vring.avail->idx = cpu_to_virtio16(_vq->vdev,
                                                 vq->split.avail_idx_shadow);
    vq->num_added++;

    pr_debug("Added buffer head %i to %p\n", head, vq);

    /* This is very unlikely, but theoretically possible.  Kick
     * just in case. */
    if (unlikely(vq->num_added == (1 << 16) - 1))
        virtqueue_kick(_vq);

    return 0;

 unmap_release:
    err_idx = i;

    if (indirect)
        i = 0;
    else
        i = head;

    for (n = 0; n < total_sg; n++) {
        if (i == err_idx)
            break;
        if (indirect) {
            vring_unmap_one_split_indirect(vq, &desc[i]);
            i = virtio16_to_cpu(_vq->vdev, desc[i].next);
        } else
            i = vring_unmap_one_split(vq, i);
    }

    if (indirect)
        kfree(desc);

    return -ENOMEM;
}

static inline int
virtqueue_add(struct virtqueue *_vq,
              struct scatterlist *sgs[],
              unsigned int total_sg,
              unsigned int out_sgs,
              unsigned int in_sgs,
              void *data,
              void *ctx,
              gfp_t gfp)
{
    struct vring_virtqueue *vq = to_vvq(_vq);

    return virtqueue_add_split(_vq, sgs, total_sg,
                               out_sgs, in_sgs, data, ctx, gfp);
}

/**
 * virtqueue_add_sgs - expose buffers to other end
 * @_vq: the struct virtqueue we're talking about.
 * @sgs: array of terminated scatterlists.
 * @out_sgs: the number of scatterlists readable by other side
 * @in_sgs: the number of scatterlists which are writable (after readable ones)
 * @data: the token identifying the buffer.
 * @gfp: how to do memory allocations (if necessary).
 *
 * Caller must ensure we don't call this with other virtqueue operations
 * at the same time (except where noted).
 *
 * Returns zero or a negative error (ie. ENOSPC, ENOMEM, EIO).
 */
int virtqueue_add_sgs(struct virtqueue *_vq,
                      struct scatterlist *sgs[],
                      unsigned int out_sgs,
                      unsigned int in_sgs,
                      void *data,
                      gfp_t gfp)
{
    unsigned int i, total_sg = 0;

    /* Count them first. */
    for (i = 0; i < out_sgs + in_sgs; i++) {
        struct scatterlist *sg;

        for (sg = sgs[i]; sg; sg = sg_next(sg))
            total_sg++;
    }
    return virtqueue_add(_vq, sgs, total_sg, out_sgs, in_sgs, data, NULL, gfp);
}
EXPORT_SYMBOL_GPL(virtqueue_add_sgs);

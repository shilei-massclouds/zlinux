/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VIRTIO_RING_H
#define _LINUX_VIRTIO_RING_H

#include <asm/barrier.h>
#include <linux/irqreturn.h>
#include <uapi/linux/virtio_ring.h>

struct virtio_device;
struct virtqueue;

/* Filter out transport-specific feature bits. */
void vring_transport_features(struct virtio_device *vdev);

/*
 * Destroys a virtqueue.  If created with vring_create_virtqueue, this
 * also frees the ring.
 */
void vring_del_virtqueue(struct virtqueue *vq);

/*
 * Creates a virtqueue and allocates the descriptor ring.  If
 * may_reduce_num is set, then this may allocate a smaller ring than
 * expected.  The caller should query virtqueue_get_vring_size to learn
 * the actual size of the ring.
 */
struct virtqueue *
vring_create_virtqueue(unsigned int index,
                       unsigned int num,
                       unsigned int vring_align,
                       struct virtio_device *vdev,
                       bool weak_barriers,
                       bool may_reduce_num,
                       bool ctx,
                       bool (*notify)(struct virtqueue *vq),
                       void (*callback)(struct virtqueue *vq),
                       const char *name);

/*
 * Barriers in virtio are tricky.  Non-SMP virtio guests can't assume
 * they're not on an SMP host system, so they need to assume real
 * barriers.  Non-SMP virtio hosts could skip the barriers, but does
 * anyone care?
 *
 * For virtio_pci on SMP, we don't need to order with respect to MMIO
 * accesses through relaxed memory I/O windows, so virt_mb() et al are
 * sufficient.
 *
 * For using virtio to talk to real devices (eg. other heterogeneous
 * CPUs) we do need real barriers.  In theory, we could be using both
 * kinds of virtio, so it's a runtime decision, and the branch is
 * actually quite cheap.
 */

static inline void virtio_mb(bool weak_barriers)
{
    if (weak_barriers)
        virt_mb();
    else
        mb();
}

static inline void virtio_rmb(bool weak_barriers)
{
    if (weak_barriers)
        virt_rmb();
    else
        dma_rmb();
}

static inline void virtio_wmb(bool weak_barriers)
{
    if (weak_barriers)
        virt_wmb();
    else
        dma_wmb();
}

#endif /* _LINUX_VIRTIO_RING_H */

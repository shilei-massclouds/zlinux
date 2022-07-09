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

#endif /* _LINUX_VIRTIO_RING_H */

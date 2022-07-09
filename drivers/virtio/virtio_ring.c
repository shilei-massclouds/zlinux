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

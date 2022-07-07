/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VIRTIO_CONFIG_H
#define _LINUX_VIRTIO_CONFIG_H

#include <linux/err.h>
#include <linux/bug.h>
#include <linux/virtio.h>
#if 0
#include <linux/virtio_byteorder.h>
#endif
#include <linux/compiler_types.h>
#include <uapi/linux/virtio_config.h>

struct irq_affinity;

struct virtio_shm_region {
    u64 addr;
    u64 len;
};

/**
 * virtio_config_ops - operations for configuring a virtio device
 * Note: Do not assume that a transport implements all of the operations
 *       getting/setting a value as a simple read/write! Generally speaking,
 *       any of @get/@set, @get_status/@set_status, or @get_features/
 *       @finalize_features are NOT safe to be called from an atomic
 *       context.
 * @get: read the value of a configuration field
 *  vdev: the virtio_device
 *  offset: the offset of the configuration field
 *  buf: the buffer to write the field value into.
 *  len: the length of the buffer
 * @set: write the value of a configuration field
 *  vdev: the virtio_device
 *  offset: the offset of the configuration field
 *  buf: the buffer to read the field value from.
 *  len: the length of the buffer
 * @generation: config generation counter (optional)
 *  vdev: the virtio_device
 *  Returns the config generation counter
 * @get_status: read the status byte
 *  vdev: the virtio_device
 *  Returns the status byte
 * @set_status: write the status byte
 *  vdev: the virtio_device
 *  status: the new status byte
 * @reset: reset the device
 *  vdev: the virtio device
 *  After this, status and feature negotiation must be done again
 *  Device must not be reset from its vq/config callbacks, or in
 *  parallel with being added/removed.
 * @find_vqs: find virtqueues and instantiate them.
 *  vdev: the virtio_device
 *  nvqs: the number of virtqueues to find
 *  vqs: on success, includes new virtqueues
 *  callbacks: array of callbacks, for each virtqueue
 *      include a NULL entry for vqs that do not need a callback
 *  names: array of virtqueue names (mainly for debugging)
 *      include a NULL entry for vqs unused by driver
 *  Returns 0 on success or error status
 * @del_vqs: free virtqueues found by find_vqs().
 * @get_features: get the array of feature bits for this device.
 *  vdev: the virtio_device
 *  Returns the first 64 feature bits (all we currently need).
 * @finalize_features: confirm what device features we'll be using.
 *  vdev: the virtio_device
 *  This sends the driver feature bits to the device: it can change
 *  the dev->feature bits if it wants.
 * Note: despite the name this can be called any number of times.
 *  Returns 0 on success or error status
 * @bus_name: return the bus name associated with the device (optional)
 *  vdev: the virtio_device
 *      This returns a pointer to the bus name a la pci_name from which
 *      the caller can then copy.
 * @set_vq_affinity: set the affinity for a virtqueue (optional).
 * @get_vq_affinity: get the affinity for a virtqueue (optional).
 * @get_shm_region: get a shared memory region based on the index.
 */
typedef void vq_callback_t(struct virtqueue *);
struct virtio_config_ops {
    void (*get)(struct virtio_device *vdev, unsigned offset,
                void *buf, unsigned len);
    void (*set)(struct virtio_device *vdev, unsigned offset,
                const void *buf, unsigned len);
    u32 (*generation)(struct virtio_device *vdev);
    u8 (*get_status)(struct virtio_device *vdev);
    void (*set_status)(struct virtio_device *vdev, u8 status);
    void (*reset)(struct virtio_device *vdev);
    int (*find_vqs)(struct virtio_device *, unsigned nvqs,
                    struct virtqueue *vqs[], vq_callback_t *callbacks[],
                    const char * const names[], const bool *ctx,
                    struct irq_affinity *desc);
    void (*del_vqs)(struct virtio_device *);
    u64 (*get_features)(struct virtio_device *vdev);
    int (*finalize_features)(struct virtio_device *vdev);
    const char *(*bus_name)(struct virtio_device *vdev);
    int (*set_vq_affinity)(struct virtqueue *vq,
                           const struct cpumask *cpu_mask);
    const struct cpumask *(*get_vq_affinity)(struct virtio_device *vdev,
                                             int index);
    bool (*get_shm_region)(struct virtio_device *vdev,
                           struct virtio_shm_region *region, u8 id);
};

#endif /* _LINUX_VIRTIO_CONFIG_H */

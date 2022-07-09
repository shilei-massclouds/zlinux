/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_VIRTIO_CONFIG_H
#define _LINUX_VIRTIO_CONFIG_H

#include <linux/err.h>
#include <linux/bug.h>
#include <linux/virtio.h>
#include <linux/virtio_byteorder.h>
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

/**
 * __virtio_test_bit - helper to test feature bits. For use by transports.
 *                     Devices should normally use virtio_has_feature,
 *                     which includes more checks.
 * @vdev: the device
 * @fbit: the feature bit
 */
static inline bool __virtio_test_bit(const struct virtio_device *vdev,
                                     unsigned int fbit)
{
    /* Did you forget to fix assumptions on max features? */
    if (__builtin_constant_p(fbit))
        BUILD_BUG_ON(fbit >= 64);
    else
        BUG_ON(fbit >= 64);

    return vdev->features & BIT_ULL(fbit);
}

/**
 * __virtio_set_bit - helper to set feature bits. For use by transports.
 * @vdev: the device
 * @fbit: the feature bit
 */
static inline void __virtio_set_bit(struct virtio_device *vdev,
                                    unsigned int fbit)
{
    /* Did you forget to fix assumptions on max features? */
    if (__builtin_constant_p(fbit))
        BUILD_BUG_ON(fbit >= 64);
    else
        BUG_ON(fbit >= 64);

    vdev->features |= BIT_ULL(fbit);
}

/**
 * __virtio_clear_bit - helper to clear feature bits. For use by transports.
 * @vdev: the device
 * @fbit: the feature bit
 */
static inline void __virtio_clear_bit(struct virtio_device *vdev,
                                      unsigned int fbit)
{
    /* Did you forget to fix assumptions on max features? */
    if (__builtin_constant_p(fbit))
        BUILD_BUG_ON(fbit >= 64);
    else
        BUG_ON(fbit >= 64);

    vdev->features &= ~BIT_ULL(fbit);
}

/* If driver didn't advertise the feature, it will never appear. */
void virtio_check_driver_offered_feature(const struct virtio_device *vdev,
                                         unsigned int fbit);

/**
 * virtio_has_feature - helper to determine if this device has this feature.
 * @vdev: the device
 * @fbit: the feature bit
 */
static inline bool virtio_has_feature(const struct virtio_device *vdev,
                                      unsigned int fbit)
{
    if (fbit < VIRTIO_TRANSPORT_F_START)
        virtio_check_driver_offered_feature(vdev, fbit);

    return __virtio_test_bit(vdev, fbit);
}

static inline bool virtio_is_little_endian(struct virtio_device *vdev)
{
    return virtio_has_feature(vdev, VIRTIO_F_VERSION_1) ||
        virtio_legacy_is_little_endian();
}

/* Memory accessors */
static inline u16 virtio16_to_cpu(struct virtio_device *vdev, __virtio16 val)
{
    return __virtio16_to_cpu(virtio_is_little_endian(vdev), val);
}

static inline __virtio16 cpu_to_virtio16(struct virtio_device *vdev, u16 val)
{
    return __cpu_to_virtio16(virtio_is_little_endian(vdev), val);
}

static inline u32 virtio32_to_cpu(struct virtio_device *vdev, __virtio32 val)
{
    return __virtio32_to_cpu(virtio_is_little_endian(vdev), val);
}

static inline __virtio32 cpu_to_virtio32(struct virtio_device *vdev, u32 val)
{
    return __cpu_to_virtio32(virtio_is_little_endian(vdev), val);
}

static inline u64 virtio64_to_cpu(struct virtio_device *vdev, __virtio64 val)
{
    return __virtio64_to_cpu(virtio_is_little_endian(vdev), val);
}

static inline __virtio64 cpu_to_virtio64(struct virtio_device *vdev, u64 val)
{
    return __cpu_to_virtio64(virtio_is_little_endian(vdev), val);
}

#define virtio_to_cpu(vdev, x) \
    _Generic((x), \
        __u8: (x), \
        __virtio16: virtio16_to_cpu((vdev), (x)), \
        __virtio32: virtio32_to_cpu((vdev), (x)), \
        __virtio64: virtio64_to_cpu((vdev), (x)) \
        )

/* Config space accessors. */
#define virtio_cread(vdev, structname, member, ptr)         \
    do {                                \
        typeof(((structname*)0)->member) virtio_cread_v;    \
                                    \
        might_sleep();                      \
        /* Sanity check: must match the member's type */    \
        typecheck(typeof(virtio_to_cpu((vdev), virtio_cread_v)), *(ptr)); \
                                    \
        switch (sizeof(virtio_cread_v)) {           \
        case 1:                         \
        case 2:                         \
        case 4:                         \
            vdev->config->get((vdev),           \
                      offsetof(structname, member), \
                      &virtio_cread_v,      \
                      sizeof(virtio_cread_v));  \
            break;                      \
        default:                        \
            __virtio_cread_many((vdev),             \
                      offsetof(structname, member), \
                      &virtio_cread_v,      \
                      1,                \
                      sizeof(virtio_cread_v));  \
            break;                      \
        }                           \
        *(ptr) = virtio_to_cpu(vdev, virtio_cread_v);       \
    } while(0)

/* Conditional config space accessors. */
#define virtio_cread_feature(vdev, fbit, structname, member, ptr)   \
    ({                                          \
        int _r = 0;                             \
        if (!virtio_has_feature(vdev, fbit))    \
            _r = -ENOENT;                       \
        else                                    \
            virtio_cread((vdev), structname, member, ptr);  \
        _r;                                     \
    })

/* Read @count fields, @bytes each. */
static inline void __virtio_cread_many(struct virtio_device *vdev,
                                       unsigned int offset,
                                       void *buf, size_t count, size_t bytes)
{
    u32 old, gen = vdev->config->generation ?
        vdev->config->generation(vdev) : 0;
    int i;

    might_sleep();
    do {
        old = gen;

        for (i = 0; i < count; i++)
            vdev->config->get(vdev, offset + bytes * i,
                      buf + i * bytes, bytes);

        gen = vdev->config->generation ? vdev->config->generation(vdev) : 0;
    } while (gen != old);
}

#endif /* _LINUX_VIRTIO_CONFIG_H */

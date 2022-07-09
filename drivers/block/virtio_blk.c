// SPDX-License-Identifier: GPL-2.0-only
//#define DEBUG
#include <linux/spinlock.h>
#include <linux/slab.h>
#if 0
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#endif
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/virtio.h>
#include <linux/virtio_blk.h>
#if 0
#include <linux/scatterlist.h>
#endif
#include <linux/string_helpers.h>
#include <linux/idr.h>
#if 0
#include <linux/blk-mq.h>
#include <linux/blk-mq-virtio.h>
#endif
#include <linux/numa.h>
#include <linux/kdev_t.h>
#include <uapi/linux/virtio_ring.h>

#define PART_BITS 4

/* The maximum number of sg elements that fit into a virtqueue */
#define VIRTIO_BLK_MAX_SG_ELEMS 32768

#if 0
static struct workqueue_struct *virtblk_wq;
#endif

static int major;
static DEFINE_IDA(vd_index_ida);

struct virtio_blk {
    /*
     * This mutex must be held by anything that may run after
     * virtblk_remove() sets vblk->vdev to NULL.
     *
     * blk-mq, virtqueue processing, and sysfs attribute code paths are
     * shut down before vblk->vdev is set to NULL and therefore do not need
     * to hold this mutex.
     */
    struct mutex vdev_mutex;
    struct virtio_device *vdev;

#if 0
    /* The disk structure for the kernel. */
    struct gendisk *disk;

    /* Block layer tags. */
    struct blk_mq_tag_set tag_set;

    /* Process context for config space updates */
    struct work_struct config_work;
#endif

    /* Ida index - used to track minor number allocations. */
    int index;

#if 0
    /* num of vqs */
    int num_vqs;
    struct virtio_blk_vq *vqs;
#endif
};

static const struct virtio_device_id id_table[] = {
    { VIRTIO_ID_BLOCK, VIRTIO_DEV_ANY_ID },
    { 0 },
};

static unsigned int features_legacy[] = {
    VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_GEOMETRY,
    VIRTIO_BLK_F_RO, VIRTIO_BLK_F_BLK_SIZE,
    VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_CONFIG_WCE,
    VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_WRITE_ZEROES,
};

static unsigned int features[] = {
    VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX, VIRTIO_BLK_F_GEOMETRY,
    VIRTIO_BLK_F_RO, VIRTIO_BLK_F_BLK_SIZE,
    VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_TOPOLOGY, VIRTIO_BLK_F_CONFIG_WCE,
    VIRTIO_BLK_F_MQ, VIRTIO_BLK_F_DISCARD, VIRTIO_BLK_F_WRITE_ZEROES,
};

static int minor_to_index(int minor)
{
    return minor >> PART_BITS;
}

static int virtblk_probe(struct virtio_device *vdev)
{
    struct virtio_blk *vblk;
    struct request_queue *q;
    int err, index;

    u32 v, blk_size, max_size, sg_elems, opt_io_size;
    u16 min_io_size;
    u8 physical_block_exp, alignment_offset;
    unsigned int queue_depth;

    if (!vdev->config->get) {
        pr_err("%s failure: config access disabled\n", __func__);
        return -EINVAL;
    }

    err = ida_simple_get(&vd_index_ida, 0, minor_to_index(1 << MINORBITS),
                         GFP_KERNEL);
    if (err < 0)
        goto out;
    index = err;

    /* We need to know how many segments before we allocate. */
    err = virtio_cread_feature(vdev, VIRTIO_BLK_F_SEG_MAX,
                               struct virtio_blk_config, seg_max,
                               &sg_elems);

    /* We need at least one SG element, whatever they say. */
    if (err || !sg_elems)
        sg_elems = 1;

    /* Prevent integer overflows and honor max vq size */
    sg_elems = min_t(u32, sg_elems, VIRTIO_BLK_MAX_SG_ELEMS - 2);

    vdev->priv = vblk = kmalloc(sizeof(*vblk), GFP_KERNEL);
    if (!vblk) {
        err = -ENOMEM;
        goto out_free_index;
    }

    mutex_init(&vblk->vdev_mutex);

    vblk->vdev = vdev;

#if 0
    INIT_WORK(&vblk->config_work, virtblk_config_changed_work);
#endif

    panic("%s: sg_elems(%d) END!\n", __func__, sg_elems);
    return 0;

#if 0
out_cleanup_disk:
    blk_cleanup_disk(vblk->disk);
out_free_tags:
    blk_mq_free_tag_set(&vblk->tag_set);
out_free_vq:
    vdev->config->del_vqs(vdev);
    kfree(vblk->vqs);
out_free_vblk:
    kfree(vblk);
#endif
out_free_index:
    ida_simple_remove(&vd_index_ida, index);
out:
    return err;
}

static void virtblk_remove(struct virtio_device *vdev)
{
    struct virtio_blk *vblk = vdev->priv;

#if 0
    /* Make sure no work handler is accessing the device. */
    flush_work(&vblk->config_work);

    del_gendisk(vblk->disk);
    blk_cleanup_queue(vblk->disk->queue);
    blk_mq_free_tag_set(&vblk->tag_set);

    mutex_lock(&vblk->vdev_mutex);

    /* Stop all the virtqueues. */
    virtio_reset_device(vdev);

    /* Virtqueues are stopped, nothing can use vblk->vdev anymore. */
    vblk->vdev = NULL;

    vdev->config->del_vqs(vdev);
    kfree(vblk->vqs);

    mutex_unlock(&vblk->vdev_mutex);

    put_disk(vblk->disk);
#endif
    panic("%s: END!\n", __func__);
}

static void virtblk_config_changed(struct virtio_device *vdev)
{
    struct virtio_blk *vblk = vdev->priv;

#if 0
    queue_work(virtblk_wq, &vblk->config_work);
#endif
    panic("%s: END!\n", __func__);
}

static struct virtio_driver virtio_blk = {
    .feature_table              = features,
    .feature_table_size         = ARRAY_SIZE(features),
    .feature_table_legacy       = features_legacy,
    .feature_table_size_legacy  = ARRAY_SIZE(features_legacy),
    .driver.name                = KBUILD_MODNAME,
    .driver.owner               = THIS_MODULE,
    .id_table                   = id_table,
    .probe                      = virtblk_probe,
    .remove                     = virtblk_remove,
    .config_changed             = virtblk_config_changed,
};

static int __init virtio_blk_init(void)
{
    int error;

#if 0
    virtblk_wq = alloc_workqueue("virtio-blk", 0, 0);
    if (!virtblk_wq)
        return -ENOMEM;

    major = register_blkdev(0, "virtblk");
    if (major < 0) {
        error = major;
        goto out_destroy_workqueue;
    }
#endif

    error = register_virtio_driver(&virtio_blk);
    if (error)
        goto out_unregister_blkdev;
    return 0;

out_unregister_blkdev:
#if 0
    unregister_blkdev(major, "virtblk");
#endif
out_destroy_workqueue:
#if 0
    destroy_workqueue(virtblk_wq);
#endif
    return error;
}

static void __exit virtio_blk_fini(void)
{
#if 0
    unregister_virtio_driver(&virtio_blk);
    unregister_blkdev(major, "virtblk");
    destroy_workqueue(virtblk_wq);
#endif
    panic("%s: END!\n", __func__);
}

module_init(virtio_blk_init);
module_exit(virtio_blk_fini);

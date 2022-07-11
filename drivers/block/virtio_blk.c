// SPDX-License-Identifier: GPL-2.0-only
//#define DEBUG
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#if 0
#include <linux/hdreg.h>
#endif
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/virtio.h>
#include <linux/virtio_blk.h>
#include <linux/scatterlist.h>
#include <linux/string_helpers.h>
#include <linux/idr.h>
#include <linux/blk-mq.h>
#include <linux/blk-mq-virtio.h>
#include <linux/numa.h>
#include <linux/kdev_t.h>
#include <uapi/linux/virtio_ring.h>

#define PART_BITS 4
#define VQ_NAME_LEN 16

/* The maximum number of sg elements that fit into a virtqueue */
#define VIRTIO_BLK_MAX_SG_ELEMS 32768

#define VIRTIO_BLK_INLINE_SG_CNT    2

#if 0
static struct workqueue_struct *virtblk_wq;
#endif

static unsigned int num_request_queues;
//module_param(num_request_queues, uint, 0644);

static int major;
static DEFINE_IDA(vd_index_ida);

struct virtio_blk_vq {
    struct virtqueue *vq;
    spinlock_t lock;
    char name[VQ_NAME_LEN];
} ____cacheline_aligned_in_smp;

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
#endif

    /* Block layer tags. */
    struct blk_mq_tag_set tag_set;

#if 0
    /* Process context for config space updates */
    struct work_struct config_work;
#endif

    /* Ida index - used to track minor number allocations. */
    int index;

    /* num of vqs */
    int num_vqs;
    struct virtio_blk_vq *vqs;
};

struct virtblk_req {
    struct virtio_blk_outhdr out_hdr;
    u8 status;
    struct sg_table sg_table;
    struct scatterlist sg[];
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

static unsigned int virtblk_queue_depth;
//module_param_named(queue_depth, virtblk_queue_depth, uint, 0444);

static int minor_to_index(int minor)
{
    return minor >> PART_BITS;
}

static void virtblk_done(struct virtqueue *vq)
{
    struct virtio_blk *vblk = vq->vdev->priv;
    bool req_done = false;
    int qid = vq->index;
    struct virtblk_req *vbr;
    unsigned long flags;
    unsigned int len;

    panic("%s: END!\n", __func__);
}

static int init_vq(struct virtio_blk *vblk)
{
    int err;
    int i;
    vq_callback_t **callbacks;
    const char **names;
    struct virtqueue **vqs;
    unsigned short num_vqs;
    struct virtio_device *vdev = vblk->vdev;
    struct irq_affinity desc = { 0, };

    err = virtio_cread_feature(vdev, VIRTIO_BLK_F_MQ,
                               struct virtio_blk_config, num_queues,
                               &num_vqs);
    if (err)
        num_vqs = 1;
    if (!err && !num_vqs) {
        pr_err("MQ advertised but zero queues reported\n");
        return -EINVAL;
    }

    num_vqs = min_t(unsigned int,
                    min_not_zero(num_request_queues, nr_cpu_ids),
                    num_vqs);

    vblk->vqs = kmalloc_array(num_vqs, sizeof(*vblk->vqs), GFP_KERNEL);
    if (!vblk->vqs)
        return -ENOMEM;

    names = kmalloc_array(num_vqs, sizeof(*names), GFP_KERNEL);
    callbacks = kmalloc_array(num_vqs, sizeof(*callbacks), GFP_KERNEL);
    vqs = kmalloc_array(num_vqs, sizeof(*vqs), GFP_KERNEL);
    if (!names || !callbacks || !vqs) {
        err = -ENOMEM;
        goto out;
    }

    for (i = 0; i < num_vqs; i++) {
        callbacks[i] = virtblk_done;
        snprintf(vblk->vqs[i].name, VQ_NAME_LEN, "req.%d", i);
        names[i] = vblk->vqs[i].name;
    }

    /* Discover virtqueues and write information to configuration.  */
    err = virtio_find_vqs(vdev, num_vqs, vqs, callbacks, names, &desc);
    if (err)
        goto out;

    for (i = 0; i < num_vqs; i++) {
        spin_lock_init(&vblk->vqs[i].lock);
        vblk->vqs[i].vq = vqs[i];
    }
    vblk->num_vqs = num_vqs;

 out:
    kfree(vqs);
    kfree(callbacks);
    kfree(names);
    if (err)
        kfree(vblk->vqs);
    return err;
}

static blk_status_t virtio_queue_rq(struct blk_mq_hw_ctx *hctx,
                                    const struct blk_mq_queue_data *bd)
{
    panic("%s: END!\n", __func__);
}

static inline void virtblk_request_done(struct request *req)
{
#if 0
    struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);

    virtblk_unmap_data(req, vbr);
    virtblk_cleanup_cmd(req);
    blk_mq_end_request(req, virtblk_result(vbr));
#endif
    panic("%s: END!\n", __func__);
}

static void virtio_commit_rqs(struct blk_mq_hw_ctx *hctx)
{
#if 0
    struct virtio_blk *vblk = hctx->queue->queuedata;
    struct virtio_blk_vq *vq = &vblk->vqs[hctx->queue_num];
    bool kick;

    spin_lock_irq(&vq->lock);
    kick = virtqueue_kick_prepare(vq->vq);
    spin_unlock_irq(&vq->lock);

    if (kick)
        virtqueue_notify(vq->vq);
#endif
    panic("%s: END!\n", __func__);
}

static int virtblk_map_queues(struct blk_mq_tag_set *set)
{
    struct virtio_blk *vblk = set->driver_data;

    return blk_mq_virtio_map_queues(&set->map[HCTX_TYPE_DEFAULT],
                                    vblk->vdev, 0);
}

static const struct blk_mq_ops virtio_mq_ops = {
    .queue_rq   = virtio_queue_rq,
    .commit_rqs = virtio_commit_rqs,
    .complete   = virtblk_request_done,
    .map_queues = virtblk_map_queues,
};

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

    err = init_vq(vblk);
    if (err)
        goto out_free_vblk;

    /* Default queue sizing is to fill the ring. */
    if (!virtblk_queue_depth) {
        queue_depth = vblk->vqs[0].vq->num_free;
        /* ... but without indirect descs, we use 2 descs per req */
        if (!virtio_has_feature(vdev, VIRTIO_RING_F_INDIRECT_DESC))
            queue_depth /= 2;
    } else {
        queue_depth = virtblk_queue_depth;
    }

    memset(&vblk->tag_set, 0, sizeof(vblk->tag_set));
    vblk->tag_set.ops = &virtio_mq_ops;
    vblk->tag_set.queue_depth = queue_depth;
    vblk->tag_set.numa_node = NUMA_NO_NODE;
    vblk->tag_set.flags = BLK_MQ_F_SHOULD_MERGE;
    vblk->tag_set.cmd_size = sizeof(struct virtblk_req) +
        sizeof(struct scatterlist) * VIRTIO_BLK_INLINE_SG_CNT;
    vblk->tag_set.driver_data = vblk;
    vblk->tag_set.nr_hw_queues = vblk->num_vqs;

    err = blk_mq_alloc_tag_set(&vblk->tag_set);
    if (err)
        goto out_free_vq;

    panic("%s: queue_depth(%d) END!\n", __func__, queue_depth);
    return 0;

#if 0
out_cleanup_disk:
    blk_cleanup_disk(vblk->disk);
out_free_tags:
    blk_mq_free_tag_set(&vblk->tag_set);
#endif
out_free_vq:
    vdev->config->del_vqs(vdev);
    kfree(vblk->vqs);
out_free_vblk:
    kfree(vblk);
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

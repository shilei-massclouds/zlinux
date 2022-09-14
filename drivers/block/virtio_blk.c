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
#define MAX_DISCARD_SEGMENTS 256u

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

    /* The disk structure for the kernel. */
    struct gendisk *disk;

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

/* We provide getgeo only to please some old bootloader/partitioning tools */
static int virtblk_getgeo(struct block_device *bd, struct hd_geometry *geo)
{
    panic("%s: END!\n", __func__);
}

static void virtblk_free_disk(struct gendisk *disk)
{
    struct virtio_blk *vblk = disk->private_data;

    ida_simple_remove(&vd_index_ida, vblk->index);
    mutex_destroy(&vblk->vdev_mutex);
    kfree(vblk);
}

static const struct block_device_operations virtblk_fops = {
    .owner      = THIS_MODULE,
    .getgeo     = virtblk_getgeo,
    .free_disk  = virtblk_free_disk,
};

static int index_to_minor(int index)
{
    return index << PART_BITS;
}

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

    spin_lock_irqsave(&vblk->vqs[qid].lock, flags);
    do {
        virtqueue_disable_cb(vq);
        while ((vbr = virtqueue_get_buf(vblk->vqs[qid].vq, &len)) != NULL) {
            struct request *req = blk_mq_rq_from_pdu(vbr);

            if (likely(!blk_should_fake_timeout(req->q)))
                blk_mq_complete_request(req);
            req_done = true;
        }
        if (unlikely(virtqueue_is_broken(vq)))
            break;
    } while (!virtqueue_enable_cb(vq));

    /* In case queue is stopped waiting for more buffers. */
    if (req_done)
        blk_mq_start_stopped_hw_queues(vblk->disk->queue, true);

    spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);
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
    printk("%s: END!\n", __func__);
    return err;
}

static int virtblk_setup_discard_write_zeroes(struct request *req, bool unmap)
{
#if 0
    unsigned short segments = blk_rq_nr_discard_segments(req);
    unsigned short n = 0;
    struct virtio_blk_discard_write_zeroes *range;
    struct bio *bio;
    u32 flags = 0;
#endif

    panic("%s: END!\n", __func__);
}

static blk_status_t virtblk_setup_cmd(struct virtio_device *vdev,
                                      struct request *req,
                                      struct virtblk_req *vbr)
{
    bool unmap = false;
    u32 type;

    vbr->out_hdr.sector = 0;

    switch (req_op(req)) {
    case REQ_OP_READ:
        type = VIRTIO_BLK_T_IN;
        vbr->out_hdr.sector = cpu_to_virtio64(vdev, blk_rq_pos(req));
        break;
    case REQ_OP_WRITE:
        type = VIRTIO_BLK_T_OUT;
        vbr->out_hdr.sector = cpu_to_virtio64(vdev, blk_rq_pos(req));
        break;
    case REQ_OP_FLUSH:
        type = VIRTIO_BLK_T_FLUSH;
        break;
    case REQ_OP_DISCARD:
        type = VIRTIO_BLK_T_DISCARD;
        break;
    case REQ_OP_WRITE_ZEROES:
        type = VIRTIO_BLK_T_WRITE_ZEROES;
        unmap = !(req->cmd_flags & REQ_NOUNMAP);
        break;
    case REQ_OP_DRV_IN:
        type = VIRTIO_BLK_T_GET_ID;
        break;
    default:
        WARN_ON_ONCE(1);
        return BLK_STS_IOERR;
    }

    vbr->out_hdr.type = cpu_to_virtio32(vdev, type);
    vbr->out_hdr.ioprio = cpu_to_virtio32(vdev, req_get_ioprio(req));

    if (type == VIRTIO_BLK_T_DISCARD || type == VIRTIO_BLK_T_WRITE_ZEROES) {
        if (virtblk_setup_discard_write_zeroes(req, unmap))
            return BLK_STS_RESOURCE;
    }

    return 0;
}

static void virtblk_unmap_data(struct request *req, struct virtblk_req *vbr)
{
    if (blk_rq_nr_phys_segments(req))
        sg_free_table_chained(&vbr->sg_table, VIRTIO_BLK_INLINE_SG_CNT);
}

static int virtblk_map_data(struct blk_mq_hw_ctx *hctx, struct request *req,
                            struct virtblk_req *vbr)
{
    int err;

    if (!blk_rq_nr_phys_segments(req))
        return 0;

    vbr->sg_table.sgl = vbr->sg;
    err = sg_alloc_table_chained(&vbr->sg_table, blk_rq_nr_phys_segments(req),
                                 vbr->sg_table.sgl, VIRTIO_BLK_INLINE_SG_CNT);
    if (unlikely(err))
        return -ENOMEM;

    return blk_rq_map_sg(hctx->queue, req, vbr->sg_table.sgl);
}

static void virtblk_cleanup_cmd(struct request *req)
{
    if (req->rq_flags & RQF_SPECIAL_PAYLOAD)
        kfree(bvec_virt(&req->special_vec));
}

static int virtblk_add_req(struct virtqueue *vq, struct virtblk_req *vbr,
                           struct scatterlist *data_sg, bool have_data)
{
    struct scatterlist hdr, status, *sgs[3];
    unsigned int num_out = 0, num_in = 0;

    sg_init_one(&hdr, &vbr->out_hdr, sizeof(vbr->out_hdr));
    sgs[num_out++] = &hdr;

    if (have_data) {
        if (vbr->out_hdr.type & cpu_to_virtio32(vq->vdev, VIRTIO_BLK_T_OUT))
            sgs[num_out++] = data_sg;
        else
            sgs[num_out + num_in++] = data_sg;
    }

    sg_init_one(&status, &vbr->status, sizeof(vbr->status));
    sgs[num_out + num_in++] = &status;

    return virtqueue_add_sgs(vq, sgs, num_out, num_in, vbr, GFP_ATOMIC);
}

static blk_status_t virtio_queue_rq(struct blk_mq_hw_ctx *hctx,
                                    const struct blk_mq_queue_data *bd)
{
    struct virtio_blk *vblk = hctx->queue->queuedata;
    struct request *req = bd->rq;
    struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);
    unsigned long flags;
    int num;
    int qid = hctx->queue_num;
    bool notify = false;
    blk_status_t status;
    int err;

    status = virtblk_setup_cmd(vblk->vdev, req, vbr);
    if (unlikely(status))
        return status;

    blk_mq_start_request(req);

    num = virtblk_map_data(hctx, req, vbr);
    if (unlikely(num < 0)) {
        virtblk_cleanup_cmd(req);
        return BLK_STS_RESOURCE;
    }

    spin_lock_irqsave(&vblk->vqs[qid].lock, flags);
    err = virtblk_add_req(vblk->vqs[qid].vq, vbr, vbr->sg_table.sgl, num);
    if (err) {
        virtqueue_kick(vblk->vqs[qid].vq);
        /* Don't stop the queue if -ENOMEM: we may have failed to
         * bounce the buffer due to global resource outage.
         */
        if (err == -ENOSPC)
            blk_mq_stop_hw_queue(hctx);
        spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);
        virtblk_unmap_data(req, vbr);
        virtblk_cleanup_cmd(req);
        switch (err) {
        case -ENOSPC:
            return BLK_STS_DEV_RESOURCE;
        case -ENOMEM:
            return BLK_STS_RESOURCE;
        default:
            return BLK_STS_IOERR;
        }
    }

    if (bd->last && virtqueue_kick_prepare(vblk->vqs[qid].vq))
        notify = true;
    spin_unlock_irqrestore(&vblk->vqs[qid].lock, flags);

    if (notify)
        virtqueue_notify(vblk->vqs[qid].vq);
    return BLK_STS_OK;
}

static inline blk_status_t virtblk_result(struct virtblk_req *vbr)
{
    switch (vbr->status) {
    case VIRTIO_BLK_S_OK:
        return BLK_STS_OK;
    case VIRTIO_BLK_S_UNSUPP:
        return BLK_STS_NOTSUPP;
    default:
        return BLK_STS_IOERR;
    }
}

static inline void virtblk_request_done(struct request *req)
{
    struct virtblk_req *vbr = blk_mq_rq_to_pdu(req);

    virtblk_unmap_data(req, vbr);
    virtblk_cleanup_cmd(req);
    blk_mq_end_request(req, virtblk_result(vbr));
    printk("########## %s: END!\n", __func__);
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

/*
 * Legacy naming scheme used for virtio devices.  We are stuck with it for
 * virtio blk but don't ever use it for any new driver.
 */
static int virtblk_name_format(char *prefix, int index, char *buf, int buflen)
{
    const int base = 'z' - 'a' + 1;
    char *begin = buf + strlen(prefix);
    char *end = buf + buflen;
    char *p;
    int unit;

    p = end - 1;
    *p = '\0';
    unit = base;
    do {
        if (p == begin)
            return -EINVAL;
        *--p = 'a' + (index % unit);
        index = (index / unit) - 1;
    } while (index >= 0);

    memmove(begin, p, end - p);
    memcpy(buf, prefix, strlen(prefix));

    return 0;
}

static int virtblk_get_cache_mode(struct virtio_device *vdev)
{
    u8 writeback;
    int err;

    err = virtio_cread_feature(vdev, VIRTIO_BLK_F_CONFIG_WCE,
                               struct virtio_blk_config, wce, &writeback);

    /*
     * If WCE is not configurable and flush is not available,
     * assume no writeback cache is in use.
     */
    if (err)
        writeback = virtio_has_feature(vdev, VIRTIO_BLK_F_FLUSH);

    return writeback;
}

static void virtblk_update_cache_mode(struct virtio_device *vdev)
{
    u8 writeback = virtblk_get_cache_mode(vdev);
    struct virtio_blk *vblk = vdev->priv;

    blk_queue_write_cache(vblk->disk->queue, writeback, false);
}

/* The queue's logical block size must be set before calling this */
static void virtblk_update_capacity(struct virtio_blk *vblk, bool resize)
{
    struct virtio_device *vdev = vblk->vdev;
    struct request_queue *q = vblk->disk->queue;
    char cap_str_2[10], cap_str_10[10];
    unsigned long long nblocks;
    u64 capacity;

    /* Host must always specify the capacity. */
    virtio_cread(vdev, struct virtio_blk_config, capacity, &capacity);

    nblocks = DIV_ROUND_UP_ULL(capacity, queue_logical_block_size(q) >> 9);

    string_get_size(nblocks, queue_logical_block_size(q),
                    STRING_UNITS_2, cap_str_2, sizeof(cap_str_2));
    string_get_size(nblocks, queue_logical_block_size(q),
                    STRING_UNITS_10, cap_str_10, sizeof(cap_str_10));

    pr_notice("[%s] %s%llu %d-byte logical blocks (%s/%s)\n",
              vblk->disk->disk_name,
              resize ? "new size: " : "",
              nblocks,
              queue_logical_block_size(q),
              cap_str_10,
              cap_str_2);

    set_capacity_and_notify(vblk->disk, capacity);
}

static const struct attribute_group virtblk_attr_group = {
#if 0
    .attrs = virtblk_attrs,
    .is_visible = virtblk_attrs_are_visible,
#endif
};

static const struct attribute_group *virtblk_attr_groups[] = {
    &virtblk_attr_group,
    NULL,
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

    vblk->disk = blk_mq_alloc_disk(&vblk->tag_set, vblk);
    if (IS_ERR(vblk->disk)) {
        err = PTR_ERR(vblk->disk);
        goto out_free_tags;
    }
    q = vblk->disk->queue;

    virtblk_name_format("vd", index, vblk->disk->disk_name, DISK_NAME_LEN);

    vblk->disk->major = major;
    vblk->disk->first_minor = index_to_minor(index);
    vblk->disk->minors = 1 << PART_BITS;
    vblk->disk->private_data = vblk;
    vblk->disk->fops = &virtblk_fops;
    vblk->index = index;

    /* configure queue flush support */
    virtblk_update_cache_mode(vdev);

    /* If disk is read-only in the host, the guest should obey */
    if (virtio_has_feature(vdev, VIRTIO_BLK_F_RO))
        set_disk_ro(vblk->disk, 1);

    /* We can handle whatever the host told us to handle. */
    blk_queue_max_segments(q, sg_elems);

    /* No real sector limit. */
    blk_queue_max_hw_sectors(q, -1U);

    max_size = virtio_max_dma_size(vdev);

    /* Host can optionally specify maximum segment size and number of
     * segments. */
    err = virtio_cread_feature(vdev, VIRTIO_BLK_F_SIZE_MAX,
                               struct virtio_blk_config, size_max, &v);
    if (!err)
        max_size = min(max_size, v);

    blk_queue_max_segment_size(q, max_size);

    /* Host can optionally specify the block size of the device */
    err = virtio_cread_feature(vdev, VIRTIO_BLK_F_BLK_SIZE,
                               struct virtio_blk_config, blk_size,
                               &blk_size);
    if (!err) {
        err = blk_validate_block_size(blk_size);
        if (err) {
            pr_err("virtio_blk: invalid block size: 0x%x\n", blk_size);
            goto out_cleanup_disk;
        }

        blk_queue_logical_block_size(q, blk_size);
    } else
        blk_size = queue_logical_block_size(q);

    /* Use topology information if available */
    err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
                               struct virtio_blk_config, physical_block_exp,
                               &physical_block_exp);
    if (!err && physical_block_exp)
        blk_queue_physical_block_size(q, blk_size * (1 << physical_block_exp));

    err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
                               struct virtio_blk_config, alignment_offset,
                               &alignment_offset);
    if (!err && alignment_offset)
        blk_queue_alignment_offset(q, blk_size * alignment_offset);

    err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
                               struct virtio_blk_config, min_io_size,
                               &min_io_size);
    if (!err && min_io_size)
        blk_queue_io_min(q, blk_size * min_io_size);

    err = virtio_cread_feature(vdev, VIRTIO_BLK_F_TOPOLOGY,
                               struct virtio_blk_config, opt_io_size,
                               &opt_io_size);
    if (!err && opt_io_size)
        blk_queue_io_opt(q, blk_size * opt_io_size);

    if (virtio_has_feature(vdev, VIRTIO_BLK_F_DISCARD)) {
        q->limits.discard_granularity = blk_size;

        virtio_cread(vdev, struct virtio_blk_config,
                     discard_sector_alignment, &v);
        q->limits.discard_alignment = v ? v << SECTOR_SHIFT : 0;

        virtio_cread(vdev, struct virtio_blk_config, max_discard_sectors, &v);
        blk_queue_max_discard_sectors(q, v ? v : UINT_MAX);

        virtio_cread(vdev, struct virtio_blk_config, max_discard_seg, &v);

        /*
         * max_discard_seg == 0 is out of spec but we always
         * handled it.
         */
        if (!v)
            v = sg_elems;
        blk_queue_max_discard_segments(q, min(v, MAX_DISCARD_SEGMENTS));

        blk_queue_flag_set(QUEUE_FLAG_DISCARD, q);
    }

    if (virtio_has_feature(vdev, VIRTIO_BLK_F_WRITE_ZEROES)) {
        virtio_cread(vdev, struct virtio_blk_config,
                     max_write_zeroes_sectors, &v);
        blk_queue_max_write_zeroes_sectors(q, v ? v : UINT_MAX);
    }

    virtblk_update_capacity(vblk, false);
    virtio_device_ready(vdev);

    err = device_add_disk(&vdev->dev, vblk->disk, virtblk_attr_groups);
    if (err)
        goto out_cleanup_disk;

    printk("%s: !\n", __func__);
    return 0;

out_cleanup_disk:
    //blk_cleanup_disk(vblk->disk);
out_free_tags:
    //blk_mq_free_tag_set(&vblk->tag_set);
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
#endif

    major = register_blkdev(0, "virtblk");
    if (major < 0) {
        error = major;
        goto out_destroy_workqueue;
    }

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

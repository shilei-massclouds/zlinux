/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2019 Google LLC
 */

#ifndef __LINUX_BLK_CRYPTO_INTERNAL_H
#define __LINUX_BLK_CRYPTO_INTERNAL_H

#include <linux/bio.h>
#include <linux/blk-mq.h>

static inline int blk_crypto_sysfs_register(struct request_queue *q)
{
    return 0;
}

static inline void blk_crypto_sysfs_unregister(struct request_queue *q) { }

static inline bool bio_crypt_rq_ctx_compatible(struct request *rq,
                           struct bio *bio)
{
    return true;
}

static inline bool bio_crypt_ctx_front_mergeable(struct request *req,
                         struct bio *bio)
{
    return true;
}

static inline bool bio_crypt_ctx_back_mergeable(struct request *req,
                        struct bio *bio)
{
    return true;
}

static inline bool bio_crypt_ctx_merge_rq(struct request *req,
                      struct request *next)
{
    return true;
}

static inline void blk_crypto_rq_set_defaults(struct request *rq) { }

static inline bool blk_crypto_rq_is_encrypted(struct request *rq)
{
    return false;
}

void __bio_crypt_free_ctx(struct bio *bio);
static inline void bio_crypt_free_ctx(struct bio *bio)
{
    if (bio_has_crypt_ctx(bio))
        __bio_crypt_free_ctx(bio);
}

#endif /* __LINUX_BLK_CRYPTO_INTERNAL_H */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2019 Google LLC
 */

#ifndef __LINUX_BLK_CRYPTO_H
#define __LINUX_BLK_CRYPTO_H

#include <linux/types.h>

#include <linux/blk_types.h>
#include <linux/blkdev.h>

struct request;
struct request_queue;

static inline bool bio_has_crypt_ctx(struct bio *bio)
{
    return false;
}

#endif /* __LINUX_BLK_CRYPTO_H */

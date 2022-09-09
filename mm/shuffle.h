// SPDX-License-Identifier: GPL-2.0
// Copyright(c) 2018 Intel Corporation. All rights reserved.
#ifndef _MM_SHUFFLE_H
#define _MM_SHUFFLE_H
#include <linux/jump_label.h>

#define SHUFFLE_ORDER (MAX_ORDER-1)

static inline bool shuffle_pick_tail(void)
{
    return false;
}

static inline void shuffle_free_memory(pg_data_t *pgdat)
{
}

static inline void shuffle_zone(struct zone *z)
{
}

static inline bool is_shuffle_order(int order)
{
    return false;
}

#endif /* _MM_SHUFFLE_H */

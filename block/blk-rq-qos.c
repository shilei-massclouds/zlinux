// SPDX-License-Identifier: GPL-2.0

#include "blk-rq-qos.h"

void __rq_qos_merge(struct rq_qos *rqos, struct request *rq,
                    struct bio *bio)
{
    do {
        if (rqos->ops->merge)
            rqos->ops->merge(rqos, rq, bio);
        rqos = rqos->next;
    } while (rqos);
}

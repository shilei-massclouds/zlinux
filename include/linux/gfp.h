/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_GFP_H
#define __LINUX_GFP_H

/*
#include <linux/mmdebug.h>
#include <linux/mmzone.h>
*/
#include <linux/stddef.h>
#include <linux/linkage.h>
//#include <linux/topology.h>

/* Plain integer GFP bitmasks. Do not use this directly. */
#define ___GFP_DMA          0x01u
#define ___GFP_HIGHMEM      0x02u
#define ___GFP_DMA32        0x04u
#define ___GFP_MOVABLE      0x08u
#define ___GFP_RECLAIMABLE  0x10u
#define ___GFP_HIGH         0x20u
#define ___GFP_IO           0x40u
#define ___GFP_FS           0x80u

#define ___GFP_DIRECT_RECLAIM   0x400u
#define ___GFP_KSWAPD_RECLAIM   0x800u

#define __GFP_IO    ((__force gfp_t)___GFP_IO)
#define __GFP_FS    ((__force gfp_t)___GFP_FS)
#define __GFP_RECLAIM \
    ((__force gfp_t)(___GFP_DIRECT_RECLAIM|___GFP_KSWAPD_RECLAIM))

#define GFP_KERNEL  (__GFP_RECLAIM | __GFP_IO | __GFP_FS)

#endif /* __LINUX_GFP_H */

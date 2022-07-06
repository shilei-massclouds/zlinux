/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_DMA_MAPPING_H
#define _LINUX_DMA_MAPPING_H

#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/err.h>
#if 0
#include <linux/dma-direction.h>
#include <linux/scatterlist.h>
#include <linux/mem_encrypt.h>
#endif
#include <linux/bug.h>

#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))

#endif /* _LINUX_DMA_MAPPING_H */

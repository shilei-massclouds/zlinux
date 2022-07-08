#ifndef _LINUX_VIRTIO_BLK_H
#define _LINUX_VIRTIO_BLK_H
/* This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE. */
#include <linux/types.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_types.h>

/* Feature bits */
#define VIRTIO_BLK_F_SIZE_MAX   1   /* Indicates maximum segment size */
#define VIRTIO_BLK_F_SEG_MAX    2   /* Indicates maximum # of segments */
#define VIRTIO_BLK_F_GEOMETRY   4   /* Legacy geometry available  */
#define VIRTIO_BLK_F_RO         5   /* Disk is read-only */
#define VIRTIO_BLK_F_BLK_SIZE   6   /* Block size of disk is available*/
#define VIRTIO_BLK_F_TOPOLOGY   10  /* Topology information is available */
#define VIRTIO_BLK_F_MQ         12  /* support more than one vq */
#define VIRTIO_BLK_F_DISCARD    13  /* DISCARD is supported */
#define VIRTIO_BLK_F_WRITE_ZEROES   14  /* WRITE ZEROES is supported */

/* Legacy feature bits */
#define VIRTIO_BLK_F_BARRIER    0   /* Does host support barriers? */
#define VIRTIO_BLK_F_SCSI       7   /* Supports scsi command passthru */
#define VIRTIO_BLK_F_FLUSH      9   /* Flush command supported */
#define VIRTIO_BLK_F_CONFIG_WCE 11  /* Writeback mode available in config */
#ifndef __KERNEL__
/* Old (deprecated) name for VIRTIO_BLK_F_FLUSH. */
#define VIRTIO_BLK_F_WCE VIRTIO_BLK_F_FLUSH
#endif

#endif /* _LINUX_VIRTIO_BLK_H */

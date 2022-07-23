/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#if 0
#include <linux/syscalls.h>
#include <linux/unistd.h>
#endif
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/major.h>
#include <linux/root_dev.h>
#include <linux/init_syscalls.h>

void  mount_block_root(char *name, int flags);
void  mount_root(void);
extern int root_mountflags;

static inline __init int create_dev(char *name, dev_t dev)
{
    init_unlink(name);
    return init_mknod(name, S_IFBLK | 0600, new_encode_dev(dev));
}

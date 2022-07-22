// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#if 0
#include <linux/fd.h>
#include <linux/tty.h>
#include <linux/suspend.h>
#include <linux/root_dev.h>
#include <linux/security.h>
#include <linux/delay.h>
#endif
#include <linux/mount.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/fs.h>
#if 0
#include <linux/initrd.h>
#include <linux/async.h>
#include <linux/fs_struct.h>
#endif
#include <linux/slab.h>
#include <linux/ramfs.h>
#include <linux/shmem_fs.h>

#if 0
#include <linux/nfs_fs.h>
#include <linux/nfs_fs_sb.h>
#include <linux/nfs_mount.h>
#include <linux/raid/detect.h>

#include "do_mounts.h"
#endif
#include <uapi/linux/mount.h>

int root_mountflags = MS_RDONLY | MS_SILENT;
static char * __initdata root_device_name;
static char __initdata saved_root_name[64];
//static int root_wait;

dev_t ROOT_DEV;

static char * __initdata root_fs_names;

static int __init root_dev_setup(char *line)
{
    strlcpy(saved_root_name, line, sizeof(saved_root_name));
    return 1;
}
__setup("root=", root_dev_setup);

static bool is_tmpfs;
static int rootfs_init_fs_context(struct fs_context *fc)
{
    if (is_tmpfs)
        return shmem_init_fs_context(fc);

    return ramfs_init_fs_context(fc);
}

struct file_system_type rootfs_fs_type = {
    .name       = "rootfs",
    .init_fs_context = rootfs_init_fs_context,
    .kill_sb    = kill_litter_super,
};

void __init init_rootfs(void)
{
    if (!saved_root_name[0] &&
        (!root_fs_names || strstr(root_fs_names, "tmpfs")))
        is_tmpfs = true;
}

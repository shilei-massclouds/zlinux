// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/ctype.h>
#if 0
#include <linux/fd.h>
#include <linux/tty.h>
#include <linux/suspend.h>
#include <linux/delay.h>
#endif
#include <linux/root_dev.h>
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

#endif
#include <uapi/linux/mount.h>
#include "do_mounts.h"

int root_mountflags = MS_RDONLY | MS_SILENT;
static char * __initdata root_device_name;
static char __initdata saved_root_name[64];
static unsigned int __initdata root_delay;
static int root_wait;

dev_t ROOT_DEV;

static char * __initdata root_mount_data;
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

static dev_t devt_from_devnum(const char *name)
{
    unsigned maj, min, offset;
    dev_t devt = 0;
    char *p, dummy;

    if (sscanf(name, "%u:%u%c", &maj, &min, &dummy) == 2 ||
        sscanf(name, "%u:%u:%u:%c", &maj, &min, &offset, &dummy) == 3) {
        devt = MKDEV(maj, min);
        if (maj != MAJOR(devt) || min != MINOR(devt))
            return 0;
    } else {
        devt = new_decode_dev(simple_strtoul(name, &p, 16));
        if (*p)
            return 0;
    }

    return devt;
}

/**
 * devt_from_partuuid - looks up the dev_t of a partition by its UUID
 * @uuid_str:   char array containing ascii UUID
 *
 * The function will return the first partition which contains a matching
 * UUID value in its partition_meta_info struct.  This does not search
 * by filesystem UUIDs.
 *
 * If @uuid_str is followed by a "/PARTNROFF=%d", then the number will be
 * extracted and used as an offset from the partition identified by the UUID.
 *
 * Returns the matching dev_t on success or 0 on failure.
 */
static dev_t devt_from_partuuid(const char *uuid_str)
{
    panic("%s: END!\n", __func__);
}

static dev_t devt_from_partlabel(const char *label)
{
    panic("%s: END!\n", __func__);
}

static dev_t devt_from_devname(const char *name)
{
    dev_t devt = 0;
    int part;
    char s[32];
    char *p;

    if (strlen(name) > 31)
        return 0;
    strcpy(s, name);
    for (p = s; *p; p++) {
        if (*p == '/')
            *p = '!';
    }

    devt = blk_lookup_devt(s, 0);
    if (devt)
        return devt;

    panic("%s: (%s, %s) END!\n", __func__, name, s);
}

/*
 *  Convert a name into device number.  We accept the following variants:
 *
 *  1) <hex_major><hex_minor> device number in hexadecimal represents itself
 *         no leading 0x, for example b302.
 *  2) /dev/nfs represents Root_NFS (0xff)
 *  3) /dev/<disk_name> represents the device number of disk
 *  4) /dev/<disk_name><decimal> represents the device number
 *         of partition - device number of disk plus the partition number
 *  5) /dev/<disk_name>p<decimal> - same as the above, that form is
 *     used when disk name of partitioned disk ends on a digit.
 *  6) PARTUUID=00112233-4455-6677-8899-AABBCCDDEEFF representing the
 *     unique id of a partition if the partition table provides it.
 *     The UUID may be either an EFI/GPT UUID, or refer to an MSDOS
 *     partition using the format SSSSSSSS-PP, where SSSSSSSS is a zero-
 *     filled hex representation of the 32-bit "NT disk signature", and PP
 *     is a zero-filled hex representation of the 1-based partition number.
 *  7) PARTUUID=<UUID>/PARTNROFF=<int> to select a partition in relation to
 *     a partition with a known unique id.
 *  8) <major>:<minor> major and minor number of the device separated by
 *     a colon.
 *  9) PARTLABEL=<name> with name being the GPT partition label.
 *     MSDOS partitions do not support labels!
 *  10) /dev/cifs represents Root_CIFS (0xfe)
 *
 *  If name doesn't have fall into the categories above, we return (0,0).
 *  block_class is used to check if something is a disk name. If the disk
 *  name contains slashes, the device name has them replaced with
 *  bangs.
 */
dev_t name_to_dev_t(const char *name)
{
    if (strcmp(name, "/dev/nfs") == 0)
        return Root_NFS;
    if (strcmp(name, "/dev/cifs") == 0)
        return Root_CIFS;
    if (strcmp(name, "/dev/ram") == 0)
        return Root_RAM0;
    if (strncmp(name, "PARTUUID=", 9) == 0)
        return devt_from_partuuid(name + 9);
    if (strncmp(name, "PARTLABEL=", 10) == 0)
        return devt_from_partlabel(name + 10);
    if (strncmp(name, "/dev/", 5) == 0)
        return devt_from_devname(name + 5);
    return devt_from_devnum(name);
}
EXPORT_SYMBOL_GPL(name_to_dev_t);

/* This can return zero length strings. Caller should check */
static int __init split_fs_names(char *page, size_t size, char *names)
{
    int count = 1;
    char *p = page;

    strlcpy(p, root_fs_names, size);
    while (*p++) {
        if (p[-1] == ',') {
            p[-1] = '\0';
            count++;
        }
    }

    return count;
}

static int __init do_mount_root(const char *name, const char *fs,
                                const int flags, const void *data)
{
    panic("%s: END!\n", __func__);
}

void __init mount_block_root(char *name, int flags)
{
    struct page *page = alloc_page(GFP_KERNEL);
    char *fs_names = page_address(page);
    char *p;
    char b[BDEVNAME_SIZE];
    int num_fs, i;

    scnprintf(b, BDEVNAME_SIZE, "unknown-block(%u,%u)",
              MAJOR(ROOT_DEV), MINOR(ROOT_DEV));
    if (root_fs_names)
        num_fs = split_fs_names(fs_names, PAGE_SIZE, root_fs_names);
    else
        num_fs = list_bdev_fs_names(fs_names, PAGE_SIZE);

 retry:
    for (i = 0, p = fs_names; i < num_fs; i++, p += strlen(p)+1) {
        int err;

        if (!*p)
            continue;
        err = do_mount_root(name, p, flags, root_mount_data);
        switch (err) {
            case 0:
                goto out;
            case -EACCES:
            case -EINVAL:
                continue;
        }
        /*
         * Allow the user to distinguish between failed sys_open
         * and bad superblock on root device.
         * and give them a list of the available devices
         */
        printk("VFS: Cannot open root device \"%s\" or %s: error %d\n",
               root_device_name, b, err);
        printk("Please append a correct \"root=\" boot option; "
               "here are the available partitions:\n");

        printk_all_partitions();
        panic("VFS: Unable to mount root fs on %s", b);
    }
    if (!(flags & SB_RDONLY)) {
        flags |= SB_RDONLY;
        goto retry;
    }

    printk("List of all partitions:\n");
    printk_all_partitions();
    printk("No filesystem could mount root, tried: ");
    for (i = 0, p = fs_names; i < num_fs; i++, p += strlen(p)+1)
        printk(" %s", p);
    printk("\n");
    panic("VFS: Unable to mount root fs on %s", b);

 out:
    put_page(page);
}

void __init mount_root(void)
{
#if 0
    if (ROOT_DEV == Root_NFS) {
        if (!mount_nfs_root())
            printk(KERN_ERR "VFS: Unable to mount root fs via NFS.\n");
        return;
    }
    if (ROOT_DEV == 0 && root_device_name && root_fs_names) {
        if (mount_nodev_root() == 0)
            return;
    }
#endif
    {
        int err = create_dev("/dev/root", ROOT_DEV);
        if (err < 0)
            pr_emerg("Failed to create /dev/root: %d\n", err);

        mount_block_root("/dev/root", root_mountflags);
        panic("%s: END!\n", __func__);
    }
}

/*
 * Prepare the namespace - decide what/where to mount, load ramdisks, etc.
 */
void __init prepare_namespace(void)
{
    if (root_delay) {
        printk(KERN_INFO "Waiting %d sec before mounting root device...\n",
               root_delay);
        //ssleep(root_delay);
    }

#if 0
    /*
     * wait for the known devices to complete their probing
     *
     * Note: this is a potential source of long boot delays.
     * For example, it is not atypical to wait 5 seconds here
     * for the touchpad of a laptop to initialize.
     */
    wait_for_device_probe();
#endif

    if (saved_root_name[0]) {
        root_device_name = saved_root_name;
        if (!strncmp(root_device_name, "mtd", 3) ||
            !strncmp(root_device_name, "ubi", 3)) {
            panic("%s: mtd or ubi!\n", __func__);
            //mount_block_root(root_device_name, root_mountflags);
            goto out;
        }
        ROOT_DEV = name_to_dev_t(root_device_name);
        if (strncmp(root_device_name, "/dev/", 5) == 0)
            root_device_name += 5;
    }

    /* wait for any asynchronous scanning to complete */
    if ((ROOT_DEV == 0) && root_wait) {
        printk(KERN_INFO "Waiting for root device %s...\n",
               saved_root_name);
#if 0
        while (driver_probe_done() != 0 ||
               (ROOT_DEV = name_to_dev_t(saved_root_name)) == 0)
            msleep(5);
        async_synchronize_full();
#endif
        panic("Waiting for root device %s...\n", saved_root_name);
    }

    mount_root();
    panic("%s: root_device_name(%s)(%x) END!\n",
          __func__, root_device_name, ROOT_DEV);
 out:
#if 0
    devtmpfs_mount();
    init_mount(".", "/", NULL, MS_MOVE, NULL);
    init_chroot(".");
#endif
    panic("%s: 2 root_device_name(%s) END!\n", __func__, root_device_name);
}

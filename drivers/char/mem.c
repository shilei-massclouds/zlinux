// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/drivers/char/mem.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Added devfs support.
 *    Jan-11-1998, C. Scott Ananian <cananian@alumni.princeton.edu>
 *  Shared /dev/zero mmapping support, Feb 2000, Kanoj Sarcar <kanoj@sgi.com>
 */

#include <linux/mm.h>
//#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/init.h>
#include <linux/tty.h>
//#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/device.h>
#include <linux/highmem.h>
#include <linux/backing-dev.h>
#include <linux/shmem_fs.h>
//#include <linux/splice.h>
#include <linux/pfn.h>
#include <linux/export.h>
#include <linux/io.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/security.h>

#define DEVMEM_MINOR    1
#define DEVPORT_MINOR   4

static struct class *mem_class;

#if 0
static const struct file_operations __maybe_unused mem_fops = {
    .llseek     = memory_lseek,
    .read       = read_mem,
    .write      = write_mem,
    .mmap       = mmap_mem,
    .open       = open_mem,
};

static const struct memdev {
    const char *name;
    umode_t mode;
    const struct file_operations *fops;
    fmode_t fmode;
} devlist[] = {
     [DEVMEM_MINOR] = { "mem", 0, &mem_fops, FMODE_UNSIGNED_OFFSET },
     [3] = { "null", 0666, &null_fops, FMODE_NOWAIT },
     [4] = { "port", 0, &port_fops, 0 },
     [5] = { "zero", 0666, &zero_fops, FMODE_NOWAIT },
     [7] = { "full", 0666, &full_fops, 0 },
     [8] = { "random", 0666, &random_fops, 0 },
     [9] = { "urandom", 0666, &urandom_fops, 0 },
    [11] = { "kmsg", 0644, &kmsg_fops, 0 },
};
#endif

static int memory_open(struct inode *inode, struct file *filp)
{
    panic("%s: END!\n", __func__);
}

static const struct file_operations memory_fops = {
    .open = memory_open,
    .llseek = noop_llseek,
};

#if 0
static char *mem_devnode(struct device *dev, umode_t *mode)
{
    if (mode && devlist[MINOR(dev->devt)].mode)
        *mode = devlist[MINOR(dev->devt)].mode;
    return NULL;
}
#endif

static int __init chr_dev_init(void)
{
#if 0
    int minor;

    if (register_chrdev(MEM_MAJOR, "mem", &memory_fops))
        printk("unable to get major %d for memory devs\n", MEM_MAJOR);

    mem_class = class_create(THIS_MODULE, "mem");
    if (IS_ERR(mem_class))
        return PTR_ERR(mem_class);

    mem_class->devnode = mem_devnode;
    for (minor = 1; minor < ARRAY_SIZE(devlist); minor++) {
        if (!devlist[minor].name)
            continue;

        /*
         * Create /dev/port?
         */
        if ((minor == DEVPORT_MINOR) && !arch_has_dev_port())
            continue;

        device_create(mem_class, NULL, MKDEV(MEM_MAJOR, minor),
                  NULL, devlist[minor].name);
    }
#endif

    return tty_init();
}

fs_initcall(chr_dev_init);

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SHM_H_
#define _LINUX_SHM_H_

#include <linux/list.h>
#include <asm/page.h>
#if 0
#include <uapi/linux/shm.h>
#include <asm/shmparam.h>
#endif

struct file;

struct sysv_shm {
    struct list_head shm_clist;
};

#define shm_init_task(task) INIT_LIST_HEAD(&(task)->sysvshm.shm_clist)

bool is_file_shm_hugepages(struct file *file);

#endif /* _LINUX_SHM_H_ */

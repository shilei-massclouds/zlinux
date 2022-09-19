// SPDX-License-Identifier: GPL-2.0
/*
 * linux/ipc/shm.c
 * Copyright (C) 1992, 1993 Krishna Balasubramanian
 *   Many improvements/fixes by Bruno Haible.
 * Replaced `struct shm_desc' by `struct vm_area_struct', July 1994.
 * Fixed the shm swap deallocation (shm_unuse()), August 1998 Andrea Arcangeli.
 *
 * /proc/sysvipc/shm support (c) 1999 Dragos Acostachioaie <dragos@iname.com>
 * BIGMEM support, Andrea Arcangeli <andrea@suse.de>
 * SMP thread shm, Jean-Luc Boyard <jean-luc.boyard@siemens.fr>
 * HIGHMEM support, Ingo Molnar <mingo@redhat.com>
 * Make shmmax, shmall, shmmni sysctl'able, Christoph Rohland <cr@sap.com>
 * Shared /dev/zero support, Kanoj Sarcar <kanoj@sgi.com>
 * Move the mm functionality over to mm/shmem.c, Christoph Rohland <cr@sap.com>
 *
 * support for audit of ipc object properties and permission changes
 * Dustin Kirkland <dustin.kirkland@us.ibm.com>
 *
 * namespaces support
 * OpenVZ, SWsoft Inc.
 * Pavel Emelianov <xemul@openvz.org>
 *
 * Better ipc lock (kern_ipc_perm.lock) handling
 * Davidlohr Bueso <davidlohr.bueso@hp.com>, June 2013.
 */

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/shm.h>
#include <linux/init.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/shmem_fs.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#if 0
#include <linux/audit.h>
#include <linux/capability.h>
#endif
#include <linux/ptrace.h>
//#include <linux/seq_file.h>
#include <linux/rwsem.h>
#include <linux/nsproxy.h>
#include <linux/mount.h>
#if 0
#include <linux/ipc_namespace.h>
#include <linux/rhashtable.h>
#endif

#include <linux/uaccess.h>

//#include "util.h"

/*
 * shm_file_operations_huge is now identical to shm_file_operations,
 * but we keep it distinct for the sake of is_file_shm_hugepages().
 */
static const struct file_operations shm_file_operations_huge = {
#if 0
    .mmap       = shm_mmap,
    .fsync      = shm_fsync,
    .release    = shm_release,
    .get_unmapped_area  = shm_get_unmapped_area,
    .llseek     = noop_llseek,
    .fallocate  = shm_fallocate,
#endif
};

bool is_file_shm_hugepages(struct file *file)
{
    return file->f_op == &shm_file_operations_huge;
}

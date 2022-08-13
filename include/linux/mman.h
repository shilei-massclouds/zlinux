/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MMAN_H
#define _LINUX_MMAN_H

#include <linux/mm.h>
#include <linux/percpu_counter.h>

#include <linux/atomic.h>
#include <uapi/linux/mman.h>

#define arch_vm_get_page_prot(vm_flags) __pgprot(0)

#endif /* _LINUX_MMAN_H */

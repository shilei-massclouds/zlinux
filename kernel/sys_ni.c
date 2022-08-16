// SPDX-License-Identifier: GPL-2.0

#include <linux/linkage.h>
#include <linux/errno.h>
#include <linux/kernel.h>

#include <asm/unistd.h>

/*
 * Non-implemented system calls get redirected here.
 */
asmlinkage long sys_ni_syscall(void)
{
    register uintptr_t a7 asm ("a7");
    panic("%s: sysnr(%lu)\n", __func__, a7);
    return -ENOSYS;
}

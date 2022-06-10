// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI initialilization and all extension implementation.
 *
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 */

#include <linux/bits.h>
#include <linux/init.h>
//#include <linux/pm.h>
//#include <linux/reboot.h>
#include <linux/errno.h>
#include <asm/sbi.h>
#include <asm/smp.h>

/* default SBI version is 0.1 */
unsigned long sbi_spec_version __ro_after_init = SBI_SPEC_VERSION_DEFAULT;
EXPORT_SYMBOL(sbi_spec_version);

struct sbiret
sbi_ecall(int ext, int fid,
          unsigned long arg0, unsigned long arg1, unsigned long arg2,
          unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    struct sbiret ret;

    register uintptr_t a0 asm ("a0") = (uintptr_t)(arg0);
    register uintptr_t a1 asm ("a1") = (uintptr_t)(arg1);
    register uintptr_t a2 asm ("a2") = (uintptr_t)(arg2);
    register uintptr_t a3 asm ("a3") = (uintptr_t)(arg3);
    register uintptr_t a4 asm ("a4") = (uintptr_t)(arg4);
    register uintptr_t a5 asm ("a5") = (uintptr_t)(arg5);
    register uintptr_t a6 asm ("a6") = (uintptr_t)(fid);
    register uintptr_t a7 asm ("a7") = (uintptr_t)(ext);
    asm volatile ("ecall"
                  : "+r" (a0), "+r" (a1)
                  : "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r" (a6), "r" (a7)
                  : "memory");
    ret.error = a0;
    ret.value = a1;

    return ret;
}
EXPORT_SYMBOL(sbi_ecall);

/**
 * sbi_console_putchar() - Writes given character to the console device.
 * @ch: The data to be written to the console.
 *
 * Return: None
 */
void sbi_console_putchar(int ch)
{
    sbi_ecall(SBI_EXT_0_1_CONSOLE_PUTCHAR, 0, ch, 0, 0, 0, 0, 0);
}
EXPORT_SYMBOL(sbi_console_putchar);

int sbi_err_map_linux_errno(int err)
{
    switch (err) {
    case SBI_SUCCESS:
        return 0;
    case SBI_ERR_DENIED:
        return -EPERM;
    case SBI_ERR_INVALID_PARAM:
        return -EINVAL;
    case SBI_ERR_INVALID_ADDRESS:
        return -EFAULT;
    case SBI_ERR_NOT_SUPPORTED:
    case SBI_ERR_FAILURE:
    default:
        return -ENOTSUPP;
    };
}
EXPORT_SYMBOL(sbi_err_map_linux_errno);

static long __sbi_base_ecall(int fid)
{
    struct sbiret ret;

    ret = sbi_ecall(SBI_EXT_BASE, fid, 0, 0, 0, 0, 0, 0);
    if (!ret.error)
        return ret.value;
    else
        return sbi_err_map_linux_errno(ret.error);
}

static inline long sbi_get_firmware_id(void)
{
    return __sbi_base_ecall(SBI_EXT_BASE_GET_IMP_ID);
}

static inline long sbi_get_firmware_version(void)
{
    return __sbi_base_ecall(SBI_EXT_BASE_GET_IMP_VERSION);
}

static inline long sbi_get_spec_version(void)
{
    return __sbi_base_ecall(SBI_EXT_BASE_GET_SPEC_VERSION);
}

void __init sbi_init(void)
{
    int ret;

    ret = sbi_get_spec_version();
    if (ret > 0)
        sbi_spec_version = ret;

    pr_info("SBI specification v%lu.%lu detected\n",
            sbi_major_version(), sbi_minor_version());

    BUG_ON(sbi_spec_is_0_1());

    pr_info("SBI implementation ID=0x%lx Version=0x%lx\n",
            sbi_get_firmware_id(), sbi_get_firmware_version());

#if 0
    if (sbi_probe_extension(SBI_EXT_TIME) > 0) {
        __sbi_set_timer = __sbi_set_timer_v02;
        pr_info("SBI TIME extension detected\n");
    } else {
        __sbi_set_timer = __sbi_set_timer_v01;
    }
    if (sbi_probe_extension(SBI_EXT_IPI) > 0) {
        __sbi_send_ipi  = __sbi_send_ipi_v02;
        pr_info("SBI IPI extension detected\n");
    } else {
        __sbi_send_ipi  = __sbi_send_ipi_v01;
    }
    if (sbi_probe_extension(SBI_EXT_RFENCE) > 0) {
        __sbi_rfence    = __sbi_rfence_v02;
        pr_info("SBI RFENCE extension detected\n");
    } else {
        __sbi_rfence    = __sbi_rfence_v01;
    }
    if ((sbi_spec_version >= sbi_mk_version(0, 3)) &&
        (sbi_probe_extension(SBI_EXT_SRST) > 0)) {
        pr_info("SBI SRST extension detected\n");
        pm_power_off = sbi_srst_power_off;
        sbi_srst_reboot_nb.notifier_call = sbi_srst_reboot;
        sbi_srst_reboot_nb.priority = 192;
        register_restart_handler(&sbi_srst_reboot_nb);
    }

    riscv_set_ipi_ops(&sbi_ipi_ops);
#endif
}

/**
 * sbi_probe_extension() - Check if an SBI extension ID is supported or not.
 * @extid: The extension ID to be probed.
 *
 * Return: Extension specific nonzero value f yes, -ENOTSUPP otherwise.
 */
int sbi_probe_extension(int extid)
{
    struct sbiret ret;

    ret = sbi_ecall(SBI_EXT_BASE, SBI_EXT_BASE_PROBE_EXT, extid, 0, 0, 0, 0, 0);
    if (!ret.error)
        if (ret.value)
            return ret.value;

    return -ENOTSUPP;
}
EXPORT_SYMBOL(sbi_probe_extension);

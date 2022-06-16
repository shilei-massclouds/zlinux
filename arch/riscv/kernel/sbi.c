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

static int (*__sbi_rfence)(int fid, const struct cpumask *cpu_mask,
                           unsigned long start, unsigned long size,
                           unsigned long arg4, unsigned long arg5)
    __ro_after_init;

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

static int
__sbi_rfence_v02_call(unsigned long fid, unsigned long hmask,
                      unsigned long hbase, unsigned long start,
                      unsigned long size,
                      unsigned long arg4, unsigned long arg5)
{
    struct sbiret ret = {0};
    int ext = SBI_EXT_RFENCE;
    int result = 0;

    switch (fid) {
    case SBI_EXT_RFENCE_REMOTE_FENCE_I:
        ret = sbi_ecall(ext, fid, hmask, hbase, 0, 0, 0, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_SFENCE_VMA:
        ret = sbi_ecall(ext, fid, hmask, hbase, start, size, 0, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID:
        ret = sbi_ecall(ext, fid, hmask, hbase, start, size, arg4, 0);
        break;

    case SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA:
        ret = sbi_ecall(ext, fid, hmask, hbase, start, size, 0, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA_VMID:
        ret = sbi_ecall(ext, fid, hmask, hbase, start, size, arg4, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA:
        ret = sbi_ecall(ext, fid, hmask, hbase, start, size, 0, 0);
        break;
    case SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA_ASID:
        ret = sbi_ecall(ext, fid, hmask, hbase, start, size, arg4, 0);
        break;
    default:
        pr_err("unknown function ID [%lu] for SBI extension [%d]\n", fid, ext);
        result = -EINVAL;
    }

    if (ret.error) {
        result = sbi_err_map_linux_errno(ret.error);
        pr_err("%s: hbase = [%lu] hmask = [0x%lx] failed (error [%d])\n",
               __func__, hbase, hmask, result);
    }

    return result;
}

static int
__sbi_rfence_v02(int fid, const struct cpumask *cpu_mask,
                 unsigned long start, unsigned long size,
                 unsigned long arg4, unsigned long arg5)
{
    unsigned long hartid, cpuid, hmask = 0, hbase = 0, htop = 0;
    int result;

    if (!cpu_mask || cpumask_empty(cpu_mask))
        cpu_mask = cpu_online_mask;

    for_each_cpu(cpuid, cpu_mask) {
        hartid = cpuid_to_hartid_map(cpuid);
        if (hmask) {
            if (hartid + BITS_PER_LONG <= htop ||
                hbase + BITS_PER_LONG <= hartid) {
                result = __sbi_rfence_v02_call(fid, hmask, hbase,
                                               start, size, arg4, arg5);
                if (result)
                    return result;
                hmask = 0;
            } else if (hartid < hbase) {
                /* shift the mask to fit lower hartid */
                hmask <<= hbase - hartid;
                hbase = hartid;
            }
        }
        if (!hmask) {
            hbase = hartid;
            htop = hartid;
        } else if (hartid > htop) {
            htop = hartid;
        }
        hmask |= BIT(hartid - hbase);
    }

    if (hmask) {
        result = __sbi_rfence_v02_call(fid, hmask, hbase,
                                       start, size, arg4, arg5);
        if (result)
            return result;
    }

    return 0;
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
#endif
    if (sbi_probe_extension(SBI_EXT_RFENCE) > 0) {
        __sbi_rfence    = __sbi_rfence_v02;
        pr_info("SBI RFENCE extension detected\n");
    } else {
        panic("%s: NO support for rfence v0.1\n", __func__);
    }
#if 0
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

/**
 * sbi_remote_fence_i() - Execute FENCE.I instruction on given remote harts.
 * @cpu_mask: A cpu mask containing all the target harts.
 *
 * Return: 0 on success, appropriate linux error code otherwise.
 */
int sbi_remote_fence_i(const struct cpumask *cpu_mask)
{
    return __sbi_rfence(SBI_EXT_RFENCE_REMOTE_FENCE_I, cpu_mask, 0, 0, 0, 0);
}
EXPORT_SYMBOL(sbi_remote_fence_i);

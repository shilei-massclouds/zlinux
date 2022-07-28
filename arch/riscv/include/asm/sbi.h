/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2015 Regents of the University of California
 * Copyright (c) 2020 Western Digital Corporation or its affiliates.
 */

#ifndef _ASM_RISCV_SBI_H
#define _ASM_RISCV_SBI_H

#include <linux/types.h>
#include <linux/cpumask.h>

#define SBI_SPEC_VERSION_DEFAULT        0x1
#define SBI_SPEC_VERSION_MAJOR_SHIFT    24
#define SBI_SPEC_VERSION_MAJOR_MASK     0x7f
#define SBI_SPEC_VERSION_MINOR_MASK     0xffffff

enum sbi_ext_id {
    SBI_EXT_0_1_SET_TIMER = 0x0,
    SBI_EXT_0_1_CONSOLE_PUTCHAR = 0x1,
    SBI_EXT_0_1_CONSOLE_GETCHAR = 0x2,
    SBI_EXT_0_1_CLEAR_IPI = 0x3,
    SBI_EXT_0_1_SEND_IPI = 0x4,
    SBI_EXT_0_1_REMOTE_FENCE_I = 0x5,
    SBI_EXT_0_1_REMOTE_SFENCE_VMA = 0x6,
    SBI_EXT_0_1_REMOTE_SFENCE_VMA_ASID = 0x7,
    SBI_EXT_0_1_SHUTDOWN = 0x8,
    SBI_EXT_BASE = 0x10,
    SBI_EXT_TIME = 0x54494D45,
    SBI_EXT_IPI = 0x735049,
    SBI_EXT_RFENCE = 0x52464E43,
    SBI_EXT_HSM = 0x48534D,
    SBI_EXT_SRST = 0x53525354,
    SBI_EXT_PMU = 0x504D55,
};

enum sbi_ext_base_fid {
    SBI_EXT_BASE_GET_SPEC_VERSION = 0,
    SBI_EXT_BASE_GET_IMP_ID,
    SBI_EXT_BASE_GET_IMP_VERSION,
    SBI_EXT_BASE_PROBE_EXT,
    SBI_EXT_BASE_GET_MVENDORID,
    SBI_EXT_BASE_GET_MARCHID,
    SBI_EXT_BASE_GET_MIMPID,
};

enum sbi_ext_rfence_fid {
    SBI_EXT_RFENCE_REMOTE_FENCE_I = 0,
    SBI_EXT_RFENCE_REMOTE_SFENCE_VMA,
    SBI_EXT_RFENCE_REMOTE_SFENCE_VMA_ASID,
    SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA_VMID,
    SBI_EXT_RFENCE_REMOTE_HFENCE_GVMA,
    SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA_ASID,
    SBI_EXT_RFENCE_REMOTE_HFENCE_VVMA,
};

enum sbi_ext_hsm_fid {
    SBI_EXT_HSM_HART_START = 0,
    SBI_EXT_HSM_HART_STOP,
    SBI_EXT_HSM_HART_STATUS,
    SBI_EXT_HSM_HART_SUSPEND,
};

enum sbi_ext_srst_fid {
    SBI_EXT_SRST_RESET = 0,
};

enum sbi_srst_reset_type {
    SBI_SRST_RESET_TYPE_SHUTDOWN = 0,
    SBI_SRST_RESET_TYPE_COLD_REBOOT,
    SBI_SRST_RESET_TYPE_WARM_REBOOT,
};

enum sbi_srst_reset_reason {
    SBI_SRST_RESET_REASON_NONE = 0,
    SBI_SRST_RESET_REASON_SYS_FAILURE,
};

/* SBI return error codes */
#define SBI_SUCCESS             0
#define SBI_ERR_FAILURE         -1
#define SBI_ERR_NOT_SUPPORTED   -2
#define SBI_ERR_INVALID_PARAM   -3
#define SBI_ERR_DENIED          -4
#define SBI_ERR_INVALID_ADDRESS -5
#define SBI_ERR_ALREADY_AVAILABLE -6
#define SBI_ERR_ALREADY_STARTED -7
#define SBI_ERR_ALREADY_STOPPED -8

struct sbiret {
    long error;
    long value;
};

extern unsigned long sbi_spec_version;

void sbi_console_putchar(int ch);

void sbi_init(void);

struct sbiret sbi_ecall(int ext, int fid, unsigned long arg0,
                        unsigned long arg1, unsigned long arg2,
                        unsigned long arg3, unsigned long arg4,
                        unsigned long arg5);

/* Check if current SBI specification version is 0.1 or not */
static inline int sbi_spec_is_0_1(void)
{
    return (sbi_spec_version == SBI_SPEC_VERSION_DEFAULT) ? 1 : 0;
}

/* Get the major version of SBI */
static inline unsigned long sbi_major_version(void)
{
    return (sbi_spec_version >> SBI_SPEC_VERSION_MAJOR_SHIFT) &
        SBI_SPEC_VERSION_MAJOR_MASK;
}

/* Get the minor version of SBI */
static inline unsigned long sbi_minor_version(void)
{
    return sbi_spec_version & SBI_SPEC_VERSION_MINOR_MASK;
}

int sbi_probe_extension(int ext);

int sbi_err_map_linux_errno(int err);

int sbi_remote_fence_i(const struct cpumask *cpu_mask);

/* Make SBI version */
static inline unsigned long
sbi_mk_version(unsigned long major, unsigned long minor)
{
    return ((major & SBI_SPEC_VERSION_MAJOR_MASK) <<
            SBI_SPEC_VERSION_MAJOR_SHIFT) | minor;
}

int sbi_remote_sfence_vma(const struct cpumask *cpu_mask,
                          unsigned long start,
                          unsigned long size);

#endif /* _ASM_RISCV_SBI_H */

/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_RISCV_CSR_H
#define _ASM_RISCV_CSR_H

#include <linux/const.h>

/* Status register flags */
#define SR_SIE  _AC(0x00000002, UL) /* Supervisor Interrupt Enable */
#define SR_SPIE _AC(0x00000020, UL) /* Previous Supervisor IE */
#define SR_SPP  _AC(0x00000100, UL) /* Previously Supervisor */
#define SR_SUM  _AC(0x00040000, UL) /* Supervisor User Memory Access */

#define SR_FS   _AC(0x00006000, UL) /* Floating-point Status */

/* Interrupt causes (minus the high bit) */
#define IRQ_S_SOFT      1
#define IRQ_S_TIMER     5
#define IRQ_S_EXT       9

#define CSR_SSTATUS     0x100
#define CSR_SIE         0x104
#define CSR_STVEC       0x105
#define CSR_SCOUNTEREN  0x106
#define CSR_SSCRATCH    0x140
#define CSR_SEPC        0x141
#define CSR_SCAUSE      0x142
#define CSR_STVAL       0x143
#define CSR_SIP         0x144
#define CSR_SATP        0x180

# define CSR_STATUS     CSR_SSTATUS
# define CSR_IE         CSR_SIE
# define CSR_TVEC       CSR_STVEC
# define CSR_SCRATCH    CSR_SSCRATCH
# define CSR_EPC        CSR_SEPC
# define CSR_CAUSE      CSR_SCAUSE
# define CSR_TVAL       CSR_STVAL
# define CSR_IP         CSR_SIP

# define SR_IE      SR_SIE
# define SR_PIE     SR_SPIE
# define SR_PP      SR_SPP

# define RV_IRQ_SOFT    IRQ_S_SOFT
# define RV_IRQ_TIMER   IRQ_S_TIMER
# define RV_IRQ_EXT     IRQ_S_EXT

#endif /* _ASM_RISCV_CSR_H */

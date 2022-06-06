/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_CSR_H
#define _ASM_RISCV_CSR_H

#include <asm/asm.h>
#include <linux/const.h>

/* Status register flags */
#define SR_SIE  _AC(0x00000002, UL) /* Supervisor Interrupt Enable */
#define SR_SPIE _AC(0x00000020, UL) /* Previous Supervisor IE */
#define SR_SPP  _AC(0x00000100, UL) /* Previously Supervisor */
#define SR_SUM  _AC(0x00040000, UL) /* Supervisor User Memory Access */

#define SR_FS   _AC(0x00006000, UL) /* Floating-point Status */

/* SATP flags */
#define SATP_MODE_39    _AC(0x8000000000000000, UL)
#define SATP_MODE_48    _AC(0x9000000000000000, UL)
#define SATP_MODE_57    _AC(0xa000000000000000, UL)

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

#ifndef __ASSEMBLY__

#define csr_swap(csr, val)  \
({                          \
    unsigned long __v = (unsigned long)(val);               \
    __asm__ __volatile__ ("csrrw %0, " __ASM_STR(csr) ", %1"\
                          : "=r" (__v) : "rK" (__v)         \
                          : "memory");                      \
    __v;                                                    \
})

#define csr_read(csr)                                   \
({                                                      \
    register unsigned long __v;                         \
    __asm__ __volatile__ ("csrr %0, " __ASM_STR(csr)    \
                          : "=r" (__v) :                \
                          : "memory");                  \
                          __v;                          \
})

#define csr_write(csr, val)     \
({                              \
    unsigned long __v = (unsigned long)(val);   \
    __asm__ __volatile__ ("csrw " __ASM_STR(csr) ", %0" \
                          : : "rK" (__v)    \
                          : "memory");      \
})

#define csr_set(csr, val)                   \
({                              \
    unsigned long __v = (unsigned long)(val);       \
    __asm__ __volatile__ ("csrs " __ASM_STR(csr) ", %0" \
                  : : "rK" (__v)            \
                  : "memory");          \
})

#define csr_read_clear(csr, val)                \
({                              \
    unsigned long __v = (unsigned long)(val);       \
    __asm__ __volatile__ ("csrrc %0, " __ASM_STR(csr) ", %1"\
                  : "=r" (__v) : "rK" (__v)     \
                  : "memory");          \
    __v;                            \
})

#define csr_clear(csr, val)                 \
({                              \
    unsigned long __v = (unsigned long)(val);       \
    __asm__ __volatile__ ("csrc " __ASM_STR(csr) ", %0" \
                  : : "rK" (__v)            \
                  : "memory");          \
})

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_CSR_H */

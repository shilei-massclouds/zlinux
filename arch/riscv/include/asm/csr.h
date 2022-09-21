/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_CSR_H
#define _ASM_RISCV_CSR_H

#include <asm/asm.h>
#include <linux/const.h>

/* Exception cause high bit - is an interrupt if set */
#define CAUSE_IRQ_FLAG      (_AC(1, UL) << (__riscv_xlen - 1))

/* Status register flags */
#define SR_SIE  _AC(0x00000002, UL) /* Supervisor Interrupt Enable */
#define SR_SPIE _AC(0x00000020, UL) /* Previous Supervisor IE */
#define SR_SPP  _AC(0x00000100, UL) /* Previously Supervisor */
#define SR_SUM  _AC(0x00040000, UL) /* Supervisor User Memory Access */

#define SR_FS           _AC(0x00006000, UL) /* Floating-point Status */
#define SR_FS_OFF       _AC(0x00000000, UL)
#define SR_FS_INITIAL   _AC(0x00002000, UL)
#define SR_FS_CLEAN     _AC(0x00004000, UL)
#define SR_FS_DIRTY     _AC(0x00006000, UL)

#define SR_SD   _AC(0x8000000000000000, UL) /* FS/XS dirty */

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

/* symbolic CSR names: */
#define CSR_CYCLE       0xc00
#define CSR_TIME        0xc01
#define CSR_INSTRET     0xc02

# define RV_IRQ_SOFT    IRQ_S_SOFT
# define RV_IRQ_TIMER   IRQ_S_TIMER
# define RV_IRQ_EXT     IRQ_S_EXT

/* IE/IP (Supervisor/Machine Interrupt Enable/Pending) flags */
#define IE_SIE  (_AC(0x1, UL) << RV_IRQ_SOFT)
#define IE_TIE  (_AC(0x1, UL) << RV_IRQ_TIMER)
#define IE_EIE  (_AC(0x1, UL) << RV_IRQ_EXT)

#define SR_IE   SR_SIE
#define SR_PIE  SR_SPIE
#define SR_PP   SR_SPP

/* SATP flags */
#define SATP_PPN        _AC(0x00000FFFFFFFFFFF, UL)
#define SATP_MODE_39    _AC(0x8000000000000000, UL)
#define SATP_MODE_48    _AC(0x9000000000000000, UL)
#define SATP_MODE_57    _AC(0xa000000000000000, UL)
#define SATP_ASID_BITS  16
#define SATP_ASID_SHIFT 44
#define SATP_ASID_MASK  _AC(0xFFFF, UL)

/* Exception causes */
#define EXC_INST_MISALIGNED 0
#define EXC_INST_ACCESS     1
#define EXC_INST_ILLEGAL    2
#define EXC_BREAKPOINT      3
#define EXC_LOAD_ACCESS     5
#define EXC_STORE_ACCESS    7
#define EXC_SYSCALL         8
#define EXC_HYPERVISOR_SYSCALL  9
#define EXC_SUPERVISOR_SYSCALL  10
#define EXC_INST_PAGE_FAULT     12
#define EXC_LOAD_PAGE_FAULT     13
#define EXC_STORE_PAGE_FAULT    15
#define EXC_INST_GUEST_PAGE_FAULT   20
#define EXC_LOAD_GUEST_PAGE_FAULT   21
#define EXC_VIRTUAL_INST_FAULT      22
#define EXC_STORE_GUEST_PAGE_FAULT  23

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

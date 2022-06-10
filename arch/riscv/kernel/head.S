/* SPDX-License-Identifier: GPL-2.0-only */

#include <asm/thread_info.h>
#include <asm/asm-offsets.h>
#include <asm/asm.h>
#include <asm/csr.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/image.h>

__HEAD
ENTRY(_start)
    /*
     * Image header expected by Linux boot-loaders.
     * The image header data structure is described in asm/image.h.
     * Do not modify it without modifying the structure and
     * all bootloaders that expects this header format!!
    /* jump to start kernel */
    j _start_kernel
    /* reserved */
    .word 0
    .balign 8
    /* Image load offset(2MB) from start of RAM */
    .dword 0x200000
    /* Effective size of kernel image */
    .dword _end - _start
    .dword __HEAD_FLAGS
    .word RISCV_HEADER_VERSION
    .word 0
    .dword 0
    .ascii RISCV_IMAGE_MAGIC
    .balign 4
    .ascii RISCV_IMAGE_MAGIC2
    .word 0

.align 2
.global relocate_enable_mmu
relocate_enable_mmu:
    /* Relocate return address */
    la a1, kernel_map
    REG_L a1, KERNEL_MAP_VIRT_ADDR(a1)
    la a2, _start
    sub a1, a1, a2
    add ra, ra, a1

    /* Point stvec to virtual address of intruction after satp write */
    la a2, 1f
    add a2, a2, a1
    csrw CSR_TVEC, a2

    /* Compute satp for kernel page tables, but don't load it yet */
    srl a2, a0, PAGE_SHIFT
    la a1, satp_mode
    REG_L a1, 0(a1)
    or a2, a2, a1

    /*
     * Load trampoline page directory, which will cause us to trap to
     * stvec if VA != PA, or simply fall through if VA == PA.  We need a
     * full fence here because setup_vm() just wrote these PTEs and we need
     * to ensure the new translations are in use.
     */
    la a0, trampoline_pg_dir
    srl a0, a0, PAGE_SHIFT
    or a0, a0, a1
    sfence.vma
    csrw CSR_SATP, a0
.align 2
1:
    /* Set trap vector to spin forever to help debug */
    la a0, .Lsecondary_park
    csrw CSR_TVEC, a0

    /* Reload the global pointer */
.option push
.option norelax
    la gp, __global_pointer$
.option pop

    /*
     * Switch to kernel page tables.
     * A full fence is necessary in order to
     * avoid using the trampoline translations,
     * which are only correct for the first superpage.
     * Fetching the fence is guarnteed to work
     * because that first superpage is translated the same way.
     */
    csrw CSR_SATP, a2
    sfence.vma

    ret

.global secondary_start_sbi
secondary_start_sbi:
    /* Mask all interrupts */
    csrw CSR_IE, zero
    csrw CSR_IP, zero

    /* Load the global pointer */
    .option push
    .option norelax
        la gp, __global_pointer$
    .option pop

    /*
     * Disable FPU to detect illegal usage of
     * floating point in kernel space
     */
    li t0, SR_FS
    csrc CSR_STATUS, t0

    /* Set trap vector to spin forever to help debug */
    la a3, .Lsecondary_park
    csrw CSR_TVEC, a3

    /* a0 contains the hartid & a1 contains boot data */
    li a2, SBI_HART_BOOT_TASK_PTR_OFFSET
    add a2, a2, a1
    REG_L tp, (a2)
    li a3, SBI_HART_BOOT_STACK_PTR_OFFSET
    add a3, a3, a1
    REG_L sp, (a3)

.Lsecondary_start_common:
    /* Enable virtual memory and relocate to virtual address */
    la a0, swapper_pg_dir
    call relocate_enable_mmu
    call setup_trap_vector
    tail smp_callin

.align 2
setup_trap_vector:
    /* Set trap vector to exception handler */
    la a0, handle_exception
    csrw CSR_TVEC, a0

    /*
     * Set sup0 scratch register to 0, indicating to exception vector that
     * we are presently executing in kernel.
     */
    csrw CSR_SCRATCH, zero
    ret

.align 2
.Lsecondary_park:
    /* We lack SMP support or have too many harts, so park this hart */
    wfi
    j .Lsecondary_park

END(_start)

ENTRY(_start_kernel)
    /* Mask all interrupts */
    csrw CSR_IE, zero
    csrw CSR_IP, zero

    /* Load the global pointer */
.option push
.option norelax
    la gp, __global_pointer$
.option pop

    /*
     * Disable FPU to detect illegal usage of
     * floating point in kernel space
     */
    li t0, SR_FS
    csrc CSR_STATUS, t0

    li t0, CONFIG_NR_CPUS
    blt a0, t0, .Lgood_cores
    tail .Lsecondary_park
.Lgood_cores:

    /* Pick one hart to run the main boot sequence */
    la a3, hart_lottery
    li a2, 1
    amoadd.w a3, a2, (a3)
    bnez a3, .Lsecondary_start

    /* Clear BSS for flat non-ELF images */
    la a3, __bss_start
    la a4, __bss_stop
    ble a4, a3, clear_bss_done
clear_bss:
    REG_S zero, (a3)
    add a3, a3, RISCV_SZPTR
    blt a3, a4, clear_bss
clear_bss_done:

    /* Save hart ID and DTB physical address */
    mv s0, a0
    mv s1, a1
    la a2, boot_cpu_hartid
    REG_S a0, (a2)

    /* Initialize page tables and relocate to virtual addresses */
    la sp, init_thread_union + THREAD_SIZE
    mv a0, s1
    call setup_vm

    la a0, early_pg_dir
    call relocate_enable_mmu

    call setup_trap_vector
    /* Restore C environment */
    la tp, init_task
    la sp, init_thread_union + THREAD_SIZE

    /* Start the kernel */
    call soc_early_init
    tail start_kernel

.Lsecondary_start:
    /* Set trap vector to spin forever to help debug */
    la a3, .Lsecondary_park
    csrw CSR_TVEC, a3

    slli a3, a0, LGREG
    la a1, __cpu_spinwait_stack_pointer
    la a2, __cpu_spinwait_task_pointer
    add a1, a3, a1
    add a2, a3, a2

    /*
     * This hart didn't win the lottery, so we wait for the winning hart to
     * get far enough along the boot process that it should continue.
     */
.Lwait_for_cpu_up:
    /* FIXME: We should WFI to save some energy here. */
    REG_L sp, (a1)
    REG_L tp, (a2)
    beqz sp, .Lwait_for_cpu_up
    beqz tp, .Lwait_for_cpu_up
    fence

    tail .Lsecondary_start_common

END(_start_kernel)

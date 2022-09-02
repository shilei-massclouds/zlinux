// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Emil Renner Berthing
 *
 * Based on arch/arm64/kernel/jump_label.c
 */
#include <linux/jump_label.h>
#include <linux/kernel.h>
//#include <linux/memory.h>
#include <linux/mutex.h>
#include <asm/bug.h>
//#include <asm/patch.h>

#define RISCV_INSN_NOP 0x00000013U
#define RISCV_INSN_JAL 0x0000006fU

void arch_jump_label_transform(struct jump_entry *entry,
                               enum jump_label_type type)
{
    panic("%s: END!\n", __func__);
}

void arch_jump_label_transform_static(struct jump_entry *entry,
                                      enum jump_label_type type)
{
    /*
     * We use the same instructions in the arch_static_branch and
     * arch_static_branch_jump inline functions, so there's no
     * need to patch them up here.
     * The core will call arch_jump_label_transform  when those
     * instructions need to be replaced.
     */
}

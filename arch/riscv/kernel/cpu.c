// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#include <linux/init.h>
//#include <linux/seq_file.h>
#include <linux/of.h>
//#include <asm/hwcap.h>
#include <asm/smp.h>
#include <asm/pgtable.h>

/*
 * Returns the hart ID of the given device tree node, or -ENODEV if the node
 * isn't an enabled and valid RISC-V hart node.
 */
int riscv_of_processor_hartid(struct device_node *node)
{
    const char *isa;
    u32 hart;

    if (!of_device_is_compatible(node, "riscv")) {
        pr_warn("Found incompatible CPU\n");
        return -ENODEV;
    }

    hart = of_get_cpu_hwid(node, 0);
    if (hart == ~0U) {
        pr_warn("Found CPU without hart ID\n");
        return -ENODEV;
    }

    if (!of_device_is_available(node)) {
        pr_info("CPU with hartid=%d is not available\n", hart);
        return -ENODEV;
    }

    if (of_property_read_string(node, "riscv,isa", &isa)) {
        pr_warn("CPU with hartid=%d has no \"riscv,isa\" property\n", hart);
        return -ENODEV;
    }
    if (isa[0] != 'r' || isa[1] != 'v') {
        pr_warn("CPU with hartid=%d has an invalid ISA of \"%s\"\n", hart, isa);
        return -ENODEV;
    }

    return hart;
}

/*
 * Find hart ID of the CPU DT node under which given DT node falls.
 *
 * To achieve this, we walk up the DT tree until we find an active
 * RISC-V core (HART) node and extract the cpuid from it.
 */
int riscv_of_parent_hartid(struct device_node *node)
{
    for (; node; node = node->parent) {
        if (of_device_is_compatible(node, "riscv"))
            return riscv_of_processor_hartid(node);
    }

    return -1;
}

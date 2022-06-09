/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_OF_FDT_H
#define _LINUX_OF_FDT_H

#ifndef __ASSEMBLY__

/* TBD: Temporary export of fdt globals - remove when code fully merged */
extern int __initdata dt_root_addr_cells;
extern int __initdata dt_root_size_cells;
extern void *initial_boot_params;

extern u64 dt_mem_next_cell(int s, const __be32 **cellp);

extern bool early_init_dt_scan(void *params);
extern bool early_init_dt_verify(void *params);
extern void early_init_fdt_scan_reserved_mem(void);

extern void unflatten_device_tree(void);

extern const char *of_flat_dt_get_machine_name(void);

extern int early_init_dt_scan_chosen_stdout(void);

extern const void *
of_get_flat_dt_prop(unsigned long node, const char *name, int *size);

#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_OF_FDT_H */

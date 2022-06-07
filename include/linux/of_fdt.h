/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_OF_FDT_H
#define _LINUX_OF_FDT_H

#ifndef __ASSEMBLY__

extern bool early_init_dt_scan(void *params);
extern bool early_init_dt_verify(void *params);
extern void early_init_fdt_scan_reserved_mem(void);

extern void unflatten_device_tree(void);

extern const char *of_flat_dt_get_machine_name(void);

extern int early_init_dt_scan_chosen_stdout(void);

#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_OF_FDT_H */

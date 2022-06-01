/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_OF_FDT_H
#define _LINUX_OF_FDT_H

#ifndef __ASSEMBLY__

extern bool early_init_dt_scan(void *params);
extern bool early_init_dt_verify(void *params);
extern void early_init_fdt_scan_reserved_mem(void);

extern void unflatten_device_tree(void);

#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_OF_FDT_H */

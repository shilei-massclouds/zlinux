/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BYTEORDER_GENERIC_H
#define _LINUX_BYTEORDER_GENERIC_H

#define cpu_to_le16     __cpu_to_le16
#define cpu_to_be32     __cpu_to_be32

#define be32_to_cpu     __be32_to_cpu
#define be32_to_cpup    __be32_to_cpup

#endif /* _LINUX_BYTEORDER_GENERIC_H */

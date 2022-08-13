/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __ASM_GENERIC_MMAN_COMMON_H
#define __ASM_GENERIC_MMAN_COMMON_H

/* 0x01 - 0x03 are defined in linux/mman.h */
#define MAP_TYPE        0x0f        /* Mask for type of mapping */
#define MAP_FIXED       0x10        /* Interpret addr exactly */
#define MAP_ANONYMOUS   0x20        /* don't use a file */

#endif /* __ASM_GENERIC_MMAN_COMMON_H */

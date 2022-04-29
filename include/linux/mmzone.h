/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MMZONE_H
#define _LINUX_MMZONE_H

#ifndef __ASSEMBLY__
#ifndef __GENERATING_BOUNDS_H

#include <linux/bitops.h>

#endif /* !__GENERATING_BOUNDS_H */

enum zone_type {
    /*
     * ZONE_DMA and ZONE_DMA32 are used when there are peripherals not able
     * to DMA to all of the addressable memory (ZONE_NORMAL).
     * On architectures where this area covers the whole 32 bit address
     * space ZONE_DMA32 is used. ZONE_DMA is left for the ones with smaller
     * DMA addressing constraints. This distinction is important as a 32bit
     * DMA mask is assumed when ZONE_DMA32 is defined. Some 64-bit
     * platforms may need both zones as they support peripherals with
     * different DMA addressing limitations.
     *
     * Some examples:
     *
     *  - i386 and x86_64 have a fixed 16M ZONE_DMA and ZONE_DMA32 for the
     *    rest of the lower 4G.
     *
     *  - arm only uses ZONE_DMA, the size, up to 4G, may vary depending on
     *    the specific device.
     *
     *  - arm64 has a fixed 1G ZONE_DMA and ZONE_DMA32 for the rest of the
     *    lower 4G.
     *
     *  - powerpc only uses ZONE_DMA, the size, up to 2G, may vary
     *    depending on the specific device.
     *
     *  - s390 uses ZONE_DMA fixed to the lower 2G.
     *
     *  - ia64 and riscv only use ZONE_DMA32.
     *
     *  - parisc uses neither.
     */
#ifdef CONFIG_ZONE_DMA32
    ZONE_DMA32,
#endif
    /*
     * Normal addressable memory is in ZONE_NORMAL. DMA operations can be
     * performed on pages in ZONE_NORMAL if the DMA devices support
     * transfers to all addressable memory.
     */
    ZONE_NORMAL,
    ZONE_MOVABLE,

    __MAX_NR_ZONES
};

#ifndef __GENERATING_BOUNDS_H

#endif /* !__GENERATING_BOUNDS_H */
#endif /* !__ASSEMBLY__ */

#endif /* _LINUX_MMZONE_H */

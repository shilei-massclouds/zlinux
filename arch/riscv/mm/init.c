// SPDX-License-Identifier: GPL-2.0-only

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/memblock.h>
#include <linux/sizes.h>
#include <linux/export.h>

#include <linux/kernel.h>
#include <linux/of_fdt.h>
#include <linux/libfdt.h>

#include <asm/fixmap.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/page.h>
#include <asm/string.h>
#include <asm/csr.h>

#include "../kernel/head.h"

#define MAX_EARLY_MAPPING_SIZE  SZ_128M

#define DTB_EARLY_BASE_VA   PGDIR_SIZE

phys_addr_t phys_ram_base __ro_after_init;
EXPORT_SYMBOL(phys_ram_base);

void *_dtb_early_va __initdata;
uintptr_t _dtb_early_pa __initdata;

unsigned long va_pa_offset;
EXPORT_SYMBOL(va_pa_offset);

unsigned long pfn_base;
EXPORT_SYMBOL(pfn_base);

unsigned long riscv_pfn_base __ro_after_init;
EXPORT_SYMBOL(riscv_pfn_base);

unsigned long
empty_zero_page[PAGE_SIZE / sizeof(unsigned long)] __page_aligned_bss;
EXPORT_SYMBOL(empty_zero_page);

struct kernel_mapping kernel_map __ro_after_init;
EXPORT_SYMBOL(kernel_map);

pgd_t swapper_pg_dir[PTRS_PER_PGD] __page_aligned_bss;

pgd_t trampoline_pg_dir[PTRS_PER_PGD] __page_aligned_bss;
pmd_t trampoline_pmd[PTRS_PER_PMD] __page_aligned_bss;

pmd_t fixmap_pmd[PTRS_PER_PMD] __page_aligned_bss;
pte_t fixmap_pte[PTRS_PER_PTE] __page_aligned_bss;

pmd_t early_pmd[PTRS_PER_PMD] __initdata __aligned(PAGE_SIZE);
pgd_t early_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);

static pmd_t __maybe_unused
early_dtb_pmd[PTRS_PER_PMD] __initdata __aligned(PAGE_SIZE);

/*
 * The default maximal physical memory size is -PAGE_OFFSET for 32-bit kernel,
 * whereas for 64-bit kernel, the end of the virtual address space is occupied
 * by the modules/BPF/kernel mappings which reduces the available size of the
 * linear mapping.
 * Limit the memory size via mem.
 */
static phys_addr_t memory_limit = -PAGE_OFFSET - SZ_4G;

static phys_addr_t dma32_phys_limit __initdata;

static bool mmu_enabled;

struct pt_alloc_ops {
    pte_t *(*get_pte_virt)(phys_addr_t pa);
    phys_addr_t (*alloc_pte)(uintptr_t va);
    pmd_t *(*get_pmd_virt)(phys_addr_t pa);
    phys_addr_t (*alloc_pmd)(uintptr_t va);
};

static struct pt_alloc_ops _pt_ops __initdata;

#define pt_ops _pt_ops

void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t prot)
{
    unsigned long addr = __fix_to_virt(idx);
    pte_t *ptep;

    BUG_ON(idx <= FIX_HOLE || idx >= __end_of_fixed_addresses);

    ptep = &fixmap_pte[pte_index(addr)];

    if (pgprot_val(prot)) {
        set_pte(ptep, pfn_pte(phys >> PAGE_SHIFT, prot));
    } else {
        pte_clear(&init_mm, addr, ptep);
        local_flush_tlb_page(addr);
    }
}

static pte_t *__init get_pte_virt(phys_addr_t pa)
{
    if (mmu_enabled) {
        clear_fixmap(FIX_PTE);
        return (pte_t *)set_fixmap_offset(FIX_PTE, pa);
    } else {
        return (pte_t *)((uintptr_t)pa);
    }
}

static phys_addr_t __init alloc_pte(void)
{
    /*
     * We only create PMD or PGD early mappings so we
     * should never reach here with MMU disabled.
     */
    BUG_ON(!mmu_enabled);

    return memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
}

static void __init
create_pte_mapping(pte_t *ptep, uintptr_t va, phys_addr_t pa,
                   phys_addr_t sz, pgprot_t prot)
{
    uintptr_t pte_idx = pte_index(va);

    BUG_ON(sz != PAGE_SIZE);

    if (pte_none(ptep[pte_idx]))
        ptep[pte_idx] = pfn_pte(PFN_DOWN(pa), prot);
}

static pmd_t *__init get_pmd_virt(phys_addr_t pa)
{
    if (mmu_enabled) {
        clear_fixmap(FIX_PMD);
        return (pmd_t *)set_fixmap_offset(FIX_PMD, pa);
    } else {
        return (pmd_t *)((uintptr_t)pa);
    }
}

static phys_addr_t __init alloc_pmd(void)
{
    if (mmu_enabled)
        return memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);

    return (uintptr_t)early_pmd;
}

static void __init
create_pmd_mapping(pmd_t *pmdp, uintptr_t va, phys_addr_t pa,
                   phys_addr_t sz, pgprot_t prot)
{
    pte_t *ptep;
    phys_addr_t pte_phys;
    uintptr_t pmd_idx = pmd_index(va);

    if (sz == PMD_SIZE) {
        if (pmd_none(pmdp[pmd_idx]))
            pmdp[pmd_idx] = pfn_pmd(PFN_DOWN(pa), prot);
        return;
    }

    if (pmd_none(pmdp[pmd_idx])) {
        pte_phys = alloc_pte();
        pmdp[pmd_idx] = pfn_pmd(PFN_DOWN(pte_phys), PAGE_TABLE);
        ptep = get_pte_virt(pte_phys);
        memset(ptep, 0, PAGE_SIZE);
    } else {
        pte_phys = PFN_PHYS(_pmd_pfn(pmdp[pmd_idx]));
        ptep = get_pte_virt(pte_phys);
    }

    create_pte_mapping(ptep, va, pa, sz, prot);
}

#define pgd_next_t              pmd_t
#define alloc_pgd_next          alloc_pmd
#define get_pgd_next_virt(__pa) get_pmd_virt(__pa)
#define fixmap_pgd_next         fixmap_pmd

#define create_pgd_next_mapping(__nextp, __va, __pa, __sz, __prot) \
    create_pmd_mapping(__nextp, __va, __pa, __sz, __prot)

static uintptr_t __init best_map_size(phys_addr_t base, phys_addr_t size)
{
    /* Upgrade to PMD_SIZE mappings whenever possible */
    if ((base & (PMD_SIZE - 1)) || (size & (PMD_SIZE - 1)))
        return PAGE_SIZE;

    return PMD_SIZE;
}

static void __init
create_pgd_mapping(pgd_t *pgdp, uintptr_t va, phys_addr_t pa,
                   phys_addr_t sz, pgprot_t prot)
{
    pgd_next_t *nextp;
    phys_addr_t next_phys;
    uintptr_t pgd_idx = pgd_index(va);

    if (sz == PGDIR_SIZE) {
        if (pgd_val(pgdp[pgd_idx]) == 0)
            pgdp[pgd_idx] = pfn_pgd(PFN_DOWN(pa), prot);
        return;
    }

    if (pgd_val(pgdp[pgd_idx]) == 0) {
        next_phys = alloc_pgd_next();
        pgdp[pgd_idx] = pfn_pgd(PFN_DOWN(next_phys), PAGE_TABLE);
        nextp = get_pgd_next_virt(next_phys);
        memset(nextp, 0, PAGE_SIZE);
    } else {
        next_phys = PFN_PHYS(_pgd_pfn(pgdp[pgd_idx]));
        nextp = get_pgd_next_virt(next_phys);
    }

    create_pgd_next_mapping(nextp, va, pa, sz, prot);
}

static inline phys_addr_t __init alloc_pte_early(uintptr_t va)
{
    /*
     * We only create PMD or PGD early mappings so we
     * should never reach here with MMU disabled.
     */
    BUG();
}

static inline pte_t *__init get_pte_virt_early(phys_addr_t pa)
{
    return (pte_t *)((uintptr_t)pa);
}

static phys_addr_t __init alloc_pmd_early(uintptr_t va)
{
    BUG_ON((va - kernel_map.virt_addr) >> PGDIR_SHIFT);

    return (uintptr_t)early_pmd;
}

static pmd_t *__init get_pmd_virt_early(phys_addr_t pa)
{
    /* Before MMU is enabled */
    return (pmd_t *)((uintptr_t)pa);
}

static __init pgprot_t pgprot_from_va(uintptr_t va)
{
    if (is_va_kernel_text(va))
        return PAGE_KERNEL_READ_EXEC;

    /*
     * In 64-bit kernel, the kernel mapping is outside the linear mapping so
     * we must protect its linear mapping alias from being executed and
     * written.
     * And rodata section is marked readonly in mark_rodata_ro.
     */
    if (is_va_kernel_lm_alias_text(va))
        return PAGE_KERNEL_READ;

    return PAGE_KERNEL;
}

static void __init create_kernel_page_table(pgd_t *pgdir, bool early)
{
    uintptr_t va, end_va;

    end_va = kernel_map.virt_addr + kernel_map.size;
    for (va = kernel_map.virt_addr; va < end_va; va += PMD_SIZE)
        create_pgd_mapping(pgdir, va,
                           kernel_map.phys_addr + (va - kernel_map.virt_addr),
                           PMD_SIZE,
                           early ? PAGE_KERNEL_EXEC : pgprot_from_va(va));
}

/*
 * Setup a 4MB mapping that encompasses the device tree: for 64-bit kernel,
 * this means 2 PMD entries whereas for 32-bit kernel, this is only 1 PGDIR
 * entry.
 */
static void __init create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
{
    uintptr_t pa = dtb_pa & ~(PMD_SIZE - 1);

    create_pgd_mapping(early_pg_dir, DTB_EARLY_BASE_VA,
                       (uintptr_t)early_dtb_pmd, PGDIR_SIZE, PAGE_TABLE);

    create_pmd_mapping(early_dtb_pmd, DTB_EARLY_BASE_VA,
                       pa, PMD_SIZE, PAGE_KERNEL);
    create_pmd_mapping(early_dtb_pmd, DTB_EARLY_BASE_VA + PMD_SIZE,
                       pa + PMD_SIZE, PMD_SIZE, PAGE_KERNEL);

    dtb_early_va = (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PMD_SIZE - 1));

    dtb_early_pa = dtb_pa;
}

asmlinkage void __init setup_vm(uintptr_t dtb_pa)
{
    pmd_t __maybe_unused fix_bmap_spmd, fix_bmap_epmd;

    kernel_map.virt_addr = KERNEL_LINK_ADDR;

    kernel_map.phys_addr = (uintptr_t)(&_start);
    kernel_map.size = (uintptr_t)(&_end) - kernel_map.phys_addr;

    kernel_map.va_pa_offset = PAGE_OFFSET - kernel_map.phys_addr;
    kernel_map.va_kernel_pa_offset = kernel_map.virt_addr - kernel_map.phys_addr;

    riscv_pfn_base = PFN_DOWN(kernel_map.phys_addr);

    /* Sanity check alignment and size */
    BUG_ON((PAGE_OFFSET % PGDIR_SIZE) != 0);
    BUG_ON((kernel_map.phys_addr % PMD_SIZE) != 0);

    /*
     * The last 4K bytes of the addressable memory can not be mapped because
     * of IS_ERR_VALUE macro.
     */
    BUG_ON((kernel_map.virt_addr + kernel_map.size) > ADDRESS_SPACE_END - SZ_4K);

    pt_ops.alloc_pte = alloc_pte_early;
    pt_ops.get_pte_virt = get_pte_virt_early;
    pt_ops.alloc_pmd = alloc_pmd_early;
    pt_ops.get_pmd_virt = get_pmd_virt_early;

    /* Setup early PGD for fixmap */
    create_pgd_mapping(early_pg_dir, FIXADDR_START,
                       (uintptr_t)fixmap_pgd_next, PGDIR_SIZE, PAGE_TABLE);

    /* Setup fixmap PMD */
    create_pmd_mapping(fixmap_pmd, FIXADDR_START,
                       (uintptr_t)fixmap_pte, PMD_SIZE, PAGE_TABLE);
    /* Setup trampoline PGD and PMD */
    create_pgd_mapping(trampoline_pg_dir, kernel_map.virt_addr,
                       (uintptr_t)trampoline_pmd, PGDIR_SIZE, PAGE_TABLE);
    create_pmd_mapping(trampoline_pmd, kernel_map.virt_addr,
                       kernel_map.phys_addr, PMD_SIZE, PAGE_KERNEL_EXEC);

    /*
     * Setup early PGD covering entire kernel which will allow
     * us to reach paging_init(). We map all memory banks later
     * in setup_vm_final() below.
     */
    create_kernel_page_table(early_pg_dir, true);

    /* Setup early mapping for FDT early scan */
    create_fdt_early_page_table(early_pg_dir, dtb_pa);

    /*
     * Bootime fixmap only can handle PMD_SIZE mapping. Thus, boot-ioremap
     * range can not span multiple pmds.
     */
    BUILD_BUG_ON((__fix_to_virt(FIX_BTMAP_BEGIN) >> PMD_SHIFT) !=
                 (__fix_to_virt(FIX_BTMAP_END) >> PMD_SHIFT));

    /*
     * Early ioremap fixmap is already created as it lies within first 2MB
     * of fixmap region. We always map PMD_SIZE. Thus, both FIX_BTMAP_END
     * FIX_BTMAP_BEGIN should lie in the same pmd. Verify that and warn
     * the user if not.
     */
    fix_bmap_spmd = fixmap_pmd[pmd_index(__fix_to_virt(FIX_BTMAP_BEGIN))];
    fix_bmap_epmd = fixmap_pmd[pmd_index(__fix_to_virt(FIX_BTMAP_END))];
    if (pmd_val(fix_bmap_spmd) != pmd_val(fix_bmap_epmd)) {
        WARN_ON(1);
        pr_warn("fixmap btmap start [%08lx] != end [%08lx]\n",
            pmd_val(fix_bmap_spmd), pmd_val(fix_bmap_epmd));
        pr_warn("fix_to_virt(FIX_BTMAP_BEGIN): %08lx\n",
            fix_to_virt(FIX_BTMAP_BEGIN));
        pr_warn("fix_to_virt(FIX_BTMAP_END):   %08lx\n",
            fix_to_virt(FIX_BTMAP_END));

        pr_warn("FIX_BTMAP_END:       %d\n", FIX_BTMAP_END);
        pr_warn("FIX_BTMAP_BEGIN:     %d\n", FIX_BTMAP_BEGIN);
    }
}

void __init setup_bootmem(void)
{
    phys_addr_t phys_ram_end;
    phys_addr_t __maybe_unused max_mapped_addr;
    phys_addr_t vmlinux_start = __pa_symbol(&_start);
    phys_addr_t vmlinux_end = __pa_symbol(&_end);

    memblock_enforce_memory_limit(memory_limit);

    /*
     * Reserve from the start of the kernel to the end of the kernel
     */
    /*
     * Make sure we align the reservation on PMD_SIZE since we will
     * map the kernel in the linear mapping as read-only: we do not want
     * any allocation to happen between _end and the next pmd aligned page.
     */
    vmlinux_end = (vmlinux_end + PMD_SIZE - 1) & PMD_MASK;

    memblock_reserve(vmlinux_start, vmlinux_end - vmlinux_start);

    phys_ram_end = memblock_end_of_DRAM();

    min_low_pfn = PFN_UP(phys_ram_base);
    max_low_pfn = max_pfn = PFN_DOWN(phys_ram_end);

    dma32_phys_limit = min(4UL * SZ_1G, (unsigned long)PFN_PHYS(max_low_pfn));
    set_max_mapnr(max_low_pfn - ARCH_PFN_OFFSET);

    //reserve_initrd_mem();

    /*
     * If DTB is built in, no need to reserve its memblock.
     * Otherwise, do reserve it but avoid using
     * early_init_fdt_reserve_self() since __pa() does
     * not work for DTB pointers that are fixmap addresses
     */
    memblock_reserve(dtb_early_pa, fdt_totalsize(dtb_early_va));

    early_init_fdt_scan_reserved_mem();
    memblock_allow_resize();
}

static void __init setup_vm_final(void)
{
    uintptr_t va, map_size;
    phys_addr_t pa, start, end;
    struct memblock_region *reg;

    /* Set mmu_enabled flag */
    mmu_enabled = true;

    /* Setup swapper PGD for fixmap */
    create_pgd_mapping(swapper_pg_dir, FIXADDR_START,
                       __pa_symbol(fixmap_pgd_next),
                       PGDIR_SIZE, PAGE_TABLE);

    /* Map all memory banks */
    for_each_memblock(memory, reg) {
        start = reg->base;
        end = start + reg->size;

        if (start >= end)
            break;
        if (memblock_is_nomap(reg))
            continue;
        if (start <= __pa(PAGE_OFFSET) && __pa(PAGE_OFFSET) < end)
            start = __pa(PAGE_OFFSET);

        map_size = best_map_size(start, end - start);
        for (pa = start; pa < end; pa += map_size) {
            va = (uintptr_t)__va(pa);
            create_pgd_mapping(swapper_pg_dir, va, pa,
                               map_size, PAGE_KERNEL_EXEC);
        }
    }

    /* Clear fixmap PTE and PMD mappings */
    clear_fixmap(FIX_PTE);
    clear_fixmap(FIX_PMD);

    /* Move to swapper page table */
    csr_write(CSR_SATP, PFN_DOWN(__pa_symbol(swapper_pg_dir)) | SATP_MODE);
    local_flush_tlb_all();
}

static void __init zone_sizes_init(void)
{
    unsigned long max_zone_pfns[MAX_NR_ZONES] = { 0, };

#ifdef CONFIG_ZONE_DMA32
    max_zone_pfns[ZONE_DMA32] = PFN_DOWN(dma32_phys_limit);
#endif
    max_zone_pfns[ZONE_NORMAL] = max_low_pfn;

    free_area_init(max_zone_pfns);
}

void __init paging_init(void)
{
    setup_bootmem();
    setup_vm_final();
}

void __init misc_mem_init(void)
{
    zone_sizes_init();
}

void __init mem_init(void)
{
    BUG_ON(!mem_map);

    high_memory = (void *)(__va(PFN_PHYS(max_low_pfn)));
    memblock_free_all();
}

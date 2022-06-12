// SPDX-License-Identifier: GPL-2.0-only

#include <linux/init.h>
#include <linux/mm.h>
#include <linux/memblock.h>
//#include <linux/initrd.h>
#include <linux/swap.h>
#include <linux/swiotlb.h>
#include <linux/sizes.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include <linux/libfdt.h>
#if 0
#include <linux/set_memory.h>
#include <linux/dma-map-ops.h>
#include <linux/crash_dump.h>
#include <linux/hugetlb.h>
#endif

#include <asm/fixmap.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#if 0
#include <asm/soc.h>
#endif
#include <asm/io.h>
#if 0
#include <asm/ptdump.h>
#include <asm/numa.h>
#endif

#include "../kernel/head.h"

#define MAX_EARLY_MAPPING_SIZE  SZ_128M

#define DTB_EARLY_BASE_VA   PGDIR_SIZE

bool pgtable_l4_enabled = true;
bool pgtable_l5_enabled = true;
EXPORT_SYMBOL(pgtable_l4_enabled);
EXPORT_SYMBOL(pgtable_l5_enabled);

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

u64 satp_mode __ro_after_init = SATP_MODE_57;
EXPORT_SYMBOL(satp_mode);

pgd_t swapper_pg_dir[PTRS_PER_PGD] __page_aligned_bss;

static pud_t trampoline_pud[PTRS_PER_PUD] __page_aligned_bss;
static pud_t fixmap_pud[PTRS_PER_PUD] __page_aligned_bss;
static pud_t early_pud[PTRS_PER_PUD] __initdata __aligned(PAGE_SIZE);

static pmd_t trampoline_pmd[PTRS_PER_PMD] __page_aligned_bss;
static pmd_t fixmap_pmd[PTRS_PER_PMD] __page_aligned_bss;
static pmd_t early_pmd[PTRS_PER_PMD] __initdata __aligned(PAGE_SIZE);

pgd_t trampoline_pg_dir[PTRS_PER_PGD] __page_aligned_bss;

static pte_t fixmap_pte[PTRS_PER_PTE] __page_aligned_bss;

pgd_t early_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);

static p4d_t __maybe_unused
early_dtb_p4d[PTRS_PER_P4D] __initdata __aligned(PAGE_SIZE);
static pud_t __maybe_unused
early_dtb_pud[PTRS_PER_PUD] __initdata __aligned(PAGE_SIZE);
static pmd_t __maybe_unused
early_dtb_pmd[PTRS_PER_PMD] __initdata __aligned(PAGE_SIZE);

static pmd_t __maybe_unused
early_dtb_pmd[PTRS_PER_PMD] __initdata __aligned(PAGE_SIZE);

static p4d_t trampoline_p4d[PTRS_PER_P4D] __page_aligned_bss;
static p4d_t fixmap_p4d[PTRS_PER_P4D] __page_aligned_bss;
static p4d_t early_p4d[PTRS_PER_P4D] __initdata __aligned(PAGE_SIZE);

/*
 * The default maximal physical memory size is -PAGE_OFFSET for 32-bit kernel,
 * whereas for 64-bit kernel, the end of the virtual address space is occupied
 * by the modules/BPF/kernel mappings which reduces the available size of the
 * linear mapping.
 * Limit the memory size via mem.
 */
static phys_addr_t memory_limit;

static phys_addr_t dma32_phys_limit __initdata;

struct pt_alloc_ops pt_ops __initdata;

#define pgd_next_t p4d_t
#define alloc_pgd_next(__va) pt_ops.alloc_p4d(__va)
#define get_pgd_next_virt(__pa) pt_ops.get_p4d_virt(__pa)
#define create_pgd_next_mapping(__nextp, __va, __pa, __sz, __prot) \
    create_p4d_mapping(__nextp, __va, __pa, __sz, __prot)
#define fixmap_pgd_next (uintptr_t)fixmap_p4d
#define trampoline_pgd_next (uintptr_t)trampoline_p4d
#define early_dtb_pgd_next (uintptr_t)early_dtb_p4d

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

static void __init
create_pte_mapping(pte_t *ptep, uintptr_t va, phys_addr_t pa,
                   phys_addr_t sz, pgprot_t prot)
{
    uintptr_t pte_idx = pte_index(va);

    BUG_ON(sz != PAGE_SIZE);

    if (pte_none(ptep[pte_idx]))
        ptep[pte_idx] = pfn_pte(PFN_DOWN(pa), prot);
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
        pte_phys = pt_ops.alloc_pte(va);
        pmdp[pmd_idx] = pfn_pmd(PFN_DOWN(pte_phys), PAGE_TABLE);
        ptep = pt_ops.get_pte_virt(pte_phys);
        memset(ptep, 0, PAGE_SIZE);
    } else {
        pte_phys = PFN_PHYS(_pmd_pfn(pmdp[pmd_idx]));
        ptep = pt_ops.get_pte_virt(pte_phys);
    }

    create_pte_mapping(ptep, va, pa, sz, prot);
}

static void __init
create_pud_mapping(pud_t *pudp, uintptr_t va, phys_addr_t pa,
                   phys_addr_t sz, pgprot_t prot)
{
    pmd_t *nextp;
    phys_addr_t next_phys;
    uintptr_t pud_index = pud_index(va);

    if (sz == PUD_SIZE) {
        if (pud_val(pudp[pud_index]) == 0)
            pudp[pud_index] = pfn_pud(PFN_DOWN(pa), prot);
        return;
    }

    if (pud_val(pudp[pud_index]) == 0) {
        next_phys = pt_ops.alloc_pmd(va);
        pudp[pud_index] = pfn_pud(PFN_DOWN(next_phys), PAGE_TABLE);
        nextp = pt_ops.get_pmd_virt(next_phys);
        memset(nextp, 0, PAGE_SIZE);
    } else {
        next_phys = PFN_PHYS(_pud_pfn(pudp[pud_index]));
        nextp = pt_ops.get_pmd_virt(next_phys);
    }

    create_pmd_mapping(nextp, va, pa, sz, prot);
}

static void __init
create_p4d_mapping(p4d_t *p4dp, uintptr_t va, phys_addr_t pa,
                   phys_addr_t sz, pgprot_t prot)
{
    pud_t *nextp;
    phys_addr_t next_phys;
    uintptr_t p4d_index = p4d_index(va);

    if (sz == P4D_SIZE) {
        if (p4d_val(p4dp[p4d_index]) == 0)
            p4dp[p4d_index] = pfn_p4d(PFN_DOWN(pa), prot);
        return;
    }

    if (p4d_val(p4dp[p4d_index]) == 0) {
        next_phys = pt_ops.alloc_pud(va);
        p4dp[p4d_index] = pfn_p4d(PFN_DOWN(next_phys), PAGE_TABLE);
        nextp = pt_ops.get_pud_virt(next_phys);
        memset(nextp, 0, PAGE_SIZE);
    } else {
        next_phys = PFN_PHYS(_p4d_pfn(p4dp[p4d_index]));
        nextp = pt_ops.get_pud_virt(next_phys);
    }

    create_pud_mapping(nextp, va, pa, sz, prot);
}

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
        next_phys = alloc_pgd_next(va);
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

    create_pgd_mapping(early_pg_dir, DTB_EARLY_BASE_VA, early_dtb_pgd_next,
                       PGDIR_SIZE, PAGE_TABLE);

    if (pgtable_l5_enabled)
        create_p4d_mapping(early_dtb_p4d, DTB_EARLY_BASE_VA,
                           (uintptr_t)early_dtb_pud, P4D_SIZE, PAGE_TABLE);

    if (pgtable_l4_enabled)
        create_pud_mapping(early_dtb_pud, DTB_EARLY_BASE_VA,
                           (uintptr_t)early_dtb_pmd, PUD_SIZE, PAGE_TABLE);

    create_pmd_mapping(early_dtb_pmd, DTB_EARLY_BASE_VA,
                       pa, PMD_SIZE, PAGE_KERNEL);
    create_pmd_mapping(early_dtb_pmd, DTB_EARLY_BASE_VA + PMD_SIZE,
                       pa + PMD_SIZE, PMD_SIZE, PAGE_KERNEL);

    dtb_early_va = (void *)DTB_EARLY_BASE_VA + (dtb_pa & (PMD_SIZE - 1));

    dtb_early_pa = dtb_pa;
}

static phys_addr_t __init alloc_pud_early(uintptr_t va)
{
    /* Only one PUD is available for early mapping */
    BUG_ON((va - kernel_map.virt_addr) >> PGDIR_SHIFT);

    return (uintptr_t)early_pud;
}

static pud_t *__init get_pud_virt_early(phys_addr_t pa)
{
    return (pud_t *)((uintptr_t)pa);
}

static phys_addr_t __init alloc_p4d_early(uintptr_t va)
{
    /* Only one P4D is available for early mapping */
    BUG_ON((va - kernel_map.virt_addr) >> PGDIR_SHIFT);

    return (uintptr_t)early_p4d;
}

static p4d_t *__init get_p4d_virt_early(phys_addr_t pa)
{
    return (p4d_t *)((uintptr_t)pa);
}

/*
 * MMU is not enabled, the page tables are allocated directly using
 * early_pmd/pud/p4d and the address returned is the physical one.
 */
void __init pt_ops_set_early(void)
{
    pt_ops.alloc_pte = alloc_pte_early;
    pt_ops.get_pte_virt = get_pte_virt_early;
    pt_ops.alloc_pmd = alloc_pmd_early;
    pt_ops.get_pmd_virt = get_pmd_virt_early;
    pt_ops.alloc_pud = alloc_pud_early;
    pt_ops.get_pud_virt = get_pud_virt_early;
    pt_ops.alloc_p4d = alloc_p4d_early;
    pt_ops.get_p4d_virt = get_p4d_virt_early;
}

static inline phys_addr_t __init alloc_pte_fixmap(uintptr_t va)
{
    return memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
}

static inline pte_t *__init get_pte_virt_fixmap(phys_addr_t pa)
{
    clear_fixmap(FIX_PTE);
    return (pte_t *)set_fixmap_offset(FIX_PTE, pa);
}

static phys_addr_t __init alloc_pmd_fixmap(uintptr_t va)
{
    return memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
}

static pmd_t *__init get_pmd_virt_fixmap(phys_addr_t pa)
{
    clear_fixmap(FIX_PMD);
    return (pmd_t *)set_fixmap_offset(FIX_PMD, pa);
}

static phys_addr_t __init alloc_pud_fixmap(uintptr_t va)
{
    return memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
}

static pud_t *__init get_pud_virt_fixmap(phys_addr_t pa)
{
    clear_fixmap(FIX_PUD);
    return (pud_t *)set_fixmap_offset(FIX_PUD, pa);
}

static phys_addr_t __init alloc_p4d_fixmap(uintptr_t va)
{
    return memblock_phys_alloc(PAGE_SIZE, PAGE_SIZE);
}

static p4d_t *__init get_p4d_virt_fixmap(phys_addr_t pa)
{
    clear_fixmap(FIX_P4D);
    return (p4d_t *)set_fixmap_offset(FIX_P4D, pa);
}

/*
 * MMU is enabled but page table setup is not complete yet.
 * fixmap page table alloc functions must be used as a means to temporarily
 * map the allocated physical pages since the linear mapping does not exist yet.
 *
 * Note that this is called with MMU disabled, hence kernel_mapping_pa_to_va,
 * but it will be used as described above.
 */
void __init pt_ops_set_fixmap(void)
{
    pt_ops.alloc_pte = kernel_mapping_pa_to_va((uintptr_t)alloc_pte_fixmap);
    pt_ops.get_pte_virt = kernel_mapping_pa_to_va((uintptr_t)get_pte_virt_fixmap);
    pt_ops.alloc_pmd = kernel_mapping_pa_to_va((uintptr_t)alloc_pmd_fixmap);
    pt_ops.get_pmd_virt = kernel_mapping_pa_to_va((uintptr_t)get_pmd_virt_fixmap);
    pt_ops.alloc_pud = kernel_mapping_pa_to_va((uintptr_t)alloc_pud_fixmap);
    pt_ops.get_pud_virt = kernel_mapping_pa_to_va((uintptr_t)get_pud_virt_fixmap);
    pt_ops.alloc_p4d = kernel_mapping_pa_to_va((uintptr_t)alloc_p4d_fixmap);
    pt_ops.get_p4d_virt = kernel_mapping_pa_to_va((uintptr_t)get_p4d_virt_fixmap);
}

static void __init disable_pgtable_l5(void)
{
    pgtable_l5_enabled = false;
    kernel_map.page_offset = PAGE_OFFSET_L4;
    satp_mode = SATP_MODE_48;
}

static void __init disable_pgtable_l4(void)
{
    pgtable_l4_enabled = false;
    kernel_map.page_offset = PAGE_OFFSET_L3;
    satp_mode = SATP_MODE_39;
}

/*
 * There is a simple way to determine if 4-level is supported by the
 * underlying hardware: establish 1:1 mapping in 4-level page table mode
 * then read SATP to see if the configuration was taken into account
 * meaning sv48 is supported.
 */
static __init void set_satp_mode(void)
{
    u64 identity_satp, hw_satp;
    bool check_l4 = false;
    uintptr_t set_satp_mode_pmd = ((unsigned long)set_satp_mode) & PMD_MASK;

    create_p4d_mapping(early_p4d, set_satp_mode_pmd, (uintptr_t)early_pud,
                       P4D_SIZE, PAGE_TABLE);
    create_pud_mapping(early_pud, set_satp_mode_pmd, (uintptr_t)early_pmd,
                       PUD_SIZE, PAGE_TABLE);
    /* Handle the case where set_satp_mode straddles 2 PMDs */
    create_pmd_mapping(early_pmd, set_satp_mode_pmd, set_satp_mode_pmd,
                       PMD_SIZE, PAGE_KERNEL_EXEC);
    create_pmd_mapping(early_pmd,
                       set_satp_mode_pmd + PMD_SIZE,
                       set_satp_mode_pmd + PMD_SIZE,
                       PMD_SIZE, PAGE_KERNEL_EXEC);

retry:
    create_pgd_mapping(early_pg_dir, set_satp_mode_pmd,
                       check_l4 ? (uintptr_t)early_pud : (uintptr_t)early_p4d,
                       PGDIR_SIZE, PAGE_TABLE);

    identity_satp = PFN_DOWN((uintptr_t)&early_pg_dir) | satp_mode;

    local_flush_tlb_all();
    csr_write(CSR_SATP, identity_satp);
    hw_satp = csr_swap(CSR_SATP, 0ULL);
    local_flush_tlb_all();

    if (hw_satp != identity_satp) {
        if (!check_l4) {
            disable_pgtable_l5();
            check_l4 = true;
            memset(early_pg_dir, 0, PAGE_SIZE);
            goto retry;
        }
        disable_pgtable_l4();
    }

    memset(early_pg_dir, 0, PAGE_SIZE);
    memset(early_p4d, 0, PAGE_SIZE);
    memset(early_pud, 0, PAGE_SIZE);
    memset(early_pmd, 0, PAGE_SIZE);
}

asmlinkage void __init setup_vm(uintptr_t dtb_pa)
{
    pmd_t __maybe_unused fix_bmap_spmd, fix_bmap_epmd;

    kernel_map.virt_addr = KERNEL_LINK_ADDR;
    kernel_map.page_offset = _AC(CONFIG_PAGE_OFFSET, UL);

    kernel_map.phys_addr = (uintptr_t)(&_start);
    kernel_map.size = (uintptr_t)(&_end) - kernel_map.phys_addr;

    set_satp_mode();

    kernel_map.va_pa_offset = PAGE_OFFSET - kernel_map.phys_addr;
    kernel_map.va_kernel_pa_offset = kernel_map.virt_addr - kernel_map.phys_addr;

    riscv_pfn_base = PFN_DOWN(kernel_map.phys_addr);

    /*
     * The default maximal physical memory size is KERN_VIRT_SIZE for 32-bit
     * kernel, whereas for 64-bit kernel, the end of the virtual address
     * space is occupied by the modules/BPF/kernel mappings which reduces
     * the available size of the linear mapping.
     */
    memory_limit = KERN_VIRT_SIZE - SZ_4G;

    /* Sanity check alignment and size */
    BUG_ON((PAGE_OFFSET % PGDIR_SIZE) != 0);
    BUG_ON((kernel_map.phys_addr % PMD_SIZE) != 0);

    /*
     * The last 4K bytes of the addressable memory can not be mapped because
     * of IS_ERR_VALUE macro.
     */
    BUG_ON((kernel_map.virt_addr + kernel_map.size) > ADDRESS_SPACE_END - SZ_4K);

    pt_ops_set_early();

    /* Setup early PGD for fixmap */
    create_pgd_mapping(early_pg_dir, FIXADDR_START,
                       fixmap_pgd_next, PGDIR_SIZE, PAGE_TABLE);

    /* Setup fixmap P4D and PUD */
    if (pgtable_l5_enabled)
        create_p4d_mapping(fixmap_p4d, FIXADDR_START,
                           (uintptr_t)fixmap_pud, P4D_SIZE, PAGE_TABLE);
    /* Setup fixmap PUD and PMD */
    if (pgtable_l4_enabled)
        create_pud_mapping(fixmap_pud, FIXADDR_START,
                           (uintptr_t)fixmap_pmd, PUD_SIZE, PAGE_TABLE);
    create_pmd_mapping(fixmap_pmd, FIXADDR_START,
                       (uintptr_t)fixmap_pte, PMD_SIZE, PAGE_TABLE);
    /* Setup trampoline PGD and PMD */
    create_pgd_mapping(trampoline_pg_dir, kernel_map.virt_addr,
                       trampoline_pgd_next, PGDIR_SIZE, PAGE_TABLE);
    if (pgtable_l5_enabled)
        create_p4d_mapping(trampoline_p4d, kernel_map.virt_addr,
                           (uintptr_t)trampoline_pud, P4D_SIZE, PAGE_TABLE);
    if (pgtable_l4_enabled)
        create_pud_mapping(trampoline_pud, kernel_map.virt_addr,
                           (uintptr_t)trampoline_pmd, PUD_SIZE, PAGE_TABLE);
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
    BUG_ON((__fix_to_virt(FIX_BTMAP_BEGIN) >> PMD_SHIFT) !=
           (__fix_to_virt(FIX_BTMAP_END) >> PMD_SHIFT));

#if 0
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

#endif
    pt_ops_set_fixmap();
}

static void __init setup_bootmem(void)
{
    phys_addr_t phys_ram_end;
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

    /*
     * Reserve from the start of the kernel to the end of the kernel
     */
    memblock_reserve(vmlinux_start, vmlinux_end - vmlinux_start);

    phys_ram_end = memblock_end_of_DRAM();
    phys_ram_base = memblock_start_of_DRAM();

    min_low_pfn = PFN_UP(phys_ram_base);
    max_low_pfn = max_pfn = PFN_DOWN(phys_ram_end);
    high_memory = (void *)(__va(PFN_PHYS(max_low_pfn)));

    dma32_phys_limit = min(4UL * SZ_1G, (unsigned long)PFN_PHYS(max_low_pfn));
    set_max_mapnr(max_low_pfn - ARCH_PFN_OFFSET);

    //reserve_initrd_mem();

    /*
     * In case the DTB is not located in a memory region we won't
     * be able to locate it later on via the linear mapping and
     * get a segfault when accessing it via __va(dtb_early_pa).
     * To avoid this situation copy DTB to a memory region.
     * Note that memblock_phys_alloc will also reserve DTB region.
     */
    if (!memblock_is_memory(dtb_early_pa)) {
        panic("%s: dtb_early_pa (%lx) is not IN memory yet!\n",
              __func__, dtb_early_pa);
    } else {
        memblock_reserve(dtb_early_pa, fdt_totalsize(dtb_early_va));
    }

    early_init_fdt_scan_reserved_mem();
    memblock_allow_resize();
}

static phys_addr_t __init alloc_pte_late(uintptr_t va)
{
    unsigned long vaddr;

    vaddr = __get_free_page(GFP_KERNEL);
    BUG_ON(!vaddr || !pgtable_pte_page_ctor(virt_to_page(vaddr)));

    return __pa(vaddr);
}

static phys_addr_t alloc_p4d_late(uintptr_t va)
{
    unsigned long vaddr;

    vaddr = __get_free_page(GFP_KERNEL);
    BUG_ON(!vaddr);
    return __pa(vaddr);
}

static phys_addr_t alloc_pud_late(uintptr_t va)
{
    unsigned long vaddr;

    vaddr = __get_free_page(GFP_KERNEL);
    BUG_ON(!vaddr);
    return __pa(vaddr);
}

static phys_addr_t __init alloc_pmd_late(uintptr_t va)
{
    unsigned long vaddr;

    vaddr = __get_free_page(GFP_KERNEL);
    BUG_ON(!vaddr || !pgtable_pmd_page_ctor(virt_to_page(vaddr)));

    return __pa(vaddr);
}

static inline pte_t *__init get_pte_virt_late(phys_addr_t pa)
{
    return (pte_t *) __va(pa);
}

static pmd_t *__init get_pmd_virt_late(phys_addr_t pa)
{
    return (pmd_t *) __va(pa);
}

static pud_t *__init get_pud_virt_late(phys_addr_t pa)
{
    return (pud_t *)__va(pa);
}

static p4d_t *__init get_p4d_virt_late(phys_addr_t pa)
{
    return (p4d_t *)__va(pa);
}

/*
 * MMU is enabled and page table setup is complete, so from now, we can use
 * generic page allocation functions to setup page table.
 */
void __init pt_ops_set_late(void)
{
    pt_ops.alloc_pte = alloc_pte_late;
    pt_ops.get_pte_virt = get_pte_virt_late;
    pt_ops.alloc_pmd = alloc_pmd_late;
    pt_ops.get_pmd_virt = get_pmd_virt_late;
    pt_ops.alloc_pud = alloc_pud_late;
    pt_ops.get_pud_virt = get_pud_virt_late;
    pt_ops.alloc_p4d = alloc_p4d_late;
    pt_ops.get_p4d_virt = get_p4d_virt_late;
}

static void __init setup_vm_final(void)
{
    u64 i;
    uintptr_t va, map_size;
    phys_addr_t pa, start, end;

    /* Setup swapper PGD for fixmap */
    create_pgd_mapping(swapper_pg_dir, FIXADDR_START,
                       __pa_symbol(fixmap_pgd_next),
                       PGDIR_SIZE, PAGE_TABLE);

    /* Map all memory banks in the linear mapping */
    for_each_mem_range(i, &start, &end) {
        if (start >= end)
            break;

        if (start <= __pa(PAGE_OFFSET) && __pa(PAGE_OFFSET) < end)
            start = __pa(PAGE_OFFSET);
        if (end >= __pa(PAGE_OFFSET) + memory_limit)
            end = __pa(PAGE_OFFSET) + memory_limit;

        map_size = best_map_size(start, end - start);
        for (pa = start; pa < end; pa += map_size) {
            va = (uintptr_t)__va(pa);

            create_pgd_mapping(swapper_pg_dir, va, pa, map_size,
                               pgprot_from_va(va));
        }
    }

    create_kernel_page_table(swapper_pg_dir, false);


    /* Clear fixmap PTE and PMD mappings */
    clear_fixmap(FIX_PTE);
    clear_fixmap(FIX_PMD);
    clear_fixmap(FIX_PUD);
    clear_fixmap(FIX_P4D);

    /* Move to swapper page table */
    csr_write(CSR_SATP, PFN_DOWN(__pa_symbol(swapper_pg_dir)) | satp_mode);
    local_flush_tlb_all();

    pt_ops_set_late();
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
    memblock_dump_all();
}

static inline void print_mlk(char *name, unsigned long b, unsigned long t)
{
    pr_notice("%12s : 0x%08lx - 0x%08lx   (%4ld kB)\n",
              name, b, t, (((t) - (b)) >> 10));
}

static inline void print_mlm(char *name, unsigned long b, unsigned long t)
{
    pr_notice("%12s : 0x%08lx - 0x%08lx   (%4ld MB)\n",
              name, b, t, (((t) - (b)) >> 20));
}

static void __init print_vm_layout(void)
{
    pr_notice("Virtual kernel memory layout:\n");
    print_mlk("fixmap", (unsigned long)FIXADDR_START,
              (unsigned long)FIXADDR_TOP);
    print_mlm("pci io", (unsigned long)PCI_IO_START,
              (unsigned long)PCI_IO_END);
    print_mlm("vmemmap", (unsigned long)VMEMMAP_START,
              (unsigned long)VMEMMAP_END);
    print_mlm("vmalloc", (unsigned long)VMALLOC_START,
              (unsigned long)VMALLOC_END);
    print_mlm("lowmem", (unsigned long)PAGE_OFFSET,
              (unsigned long)high_memory);
    print_mlm("kernel", (unsigned long)KERNEL_LINK_ADDR,
              (unsigned long)ADDRESS_SPACE_END);
}

void __init mem_init(void)
{
    BUG_ON(!mem_map);

    if (swiotlb_force == SWIOTLB_FORCE || max_pfn > PFN_DOWN(dma32_phys_limit))
        swiotlb_init(1);
    else
        swiotlb_force = SWIOTLB_NO_FORCE;

    memblock_free_all();

    print_vm_layout();
}

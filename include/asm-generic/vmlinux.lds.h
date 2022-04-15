/*
 * Helper macros to support writing architecture specific
 * linker scripts.
 */

/* Align . to a 8 byte boundary equals to maximum function alignment. */
#define ALIGN_FUNCTION()  . = ALIGN(8)

#ifndef LOAD_OFFSET
#define LOAD_OFFSET 0
#endif

#define TEXT_MAIN .text
#define DATA_MAIN .data
#define SBSS_MAIN .sbss
#define BSS_MAIN .bss

#define MEM_KEEP(sec)
#define MEM_DISCARD(sec) *(.mem##sec)

/* Section used for early init (in .S files) */
#define HEAD_TEXT   KEEP(*(.head.text))

#define HEAD_TEXT_SECTION \
    .head.text : AT(ADDR(.head.text) - LOAD_OFFSET) { \
        HEAD_TEXT \
    }

#define INIT_TEXT               \
    *(.init.text .init.text.*)  \
    *(.text.startup)            \
    MEM_DISCARD(init.text*)

#define INIT_TEXT_SECTION(inittext_align)   \
    . = ALIGN(inittext_align);              \
    .init.text : AT(ADDR(.init.text) - LOAD_OFFSET) {   \
        _sinittext = .; \
        INIT_TEXT       \
        _einittext = .; \
    }

/* init and exit section handling */
#define INIT_DATA                       \
    *(.init.data init.data.*)           \
    MEM_DISCARD(init.data*)             \
    *(.init.rodata .init.rodata.*)      \
    MEM_DISCARD(init.rodata)

#define INIT_DATA_SECTION(initsetup_align)  \
    .init.data : AT(ADDR(.init.data) - LOAD_OFFSET) { \
        INIT_DATA   \
    }

/*
 * .text section. Map to function alignment to avoid address changes
 * during second ld run in second ld pass when generating System.map
 *
 * TEXT_MAIN here will match .text.fixup and .text.unlikely if dead
 * code elimination is enabled, so these sections should be converted
 * to use ".." first.
 */
#define TEXT_TEXT       \
    ALIGN_FUNCTION();   \
    *(.text.hot TEXT_MAIN .text.fixup .text.unlikely) \
    *(.text..refcount)  \
    *(.ref.text)        \
    MEM_KEEP(init.text*)\
    MEM_KEEP(exit.text*)

/*
 * bss (Block Started by Symbol) - uninitialized data
 * zeroed during startup
 */
#define SBSS(sbss_align)    \
    . = ALIGN(sbss_align);  \
    .sbss : AT(ADDR(.sbss) - LOAD_OFFSET) { \
        *(.dynsbss)     \
        *(SBSS_MAIN)    \
        *(.scommon)     \
    }

#define BSS_SECTION(sbss_align, bss_align, stop_align) \
    . = ALIGN(sbss_align);  \
    __bss_start = .;        \
    SBSS(sbss_align)        \
    BSS(bss_align)          \
    . = ALIGN(stop_align);  \
    __bss_stop = .;

#define BSS(bss_align)      \
    . = ALIGN(bss_align);   \
    .bss : AT(ADDR(.bss) - LOAD_OFFSET) {   \
        . = ALIGN(PAGE_SIZE);   \
        *(.bss..page_aligned)   \
        . = ALIGN(PAGE_SIZE);   \
        *(.dynbss)              \
        *(BSS_MAIN)             \
        *(COMMON)               \
    }

#define INIT_TASK_DATA(align)   \
    . = ALIGN(align);           \
    __start_init_task = .;      \
    init_thread_union = .;      \
    init_stack = .;             \
    KEEP(*(.data..init_task))   \
    KEEP(*(.data..init_thread_info))        \
    . = __start_init_task + THREAD_SIZE;    \
    __end_init_task = .;

/*
 * .data section
 */
#define DATA_DATA \
    *(DATA_MAIN)

/*
 * Writeable data.
 * All sections are combined in a single .data section.
 * The sections following CONSTRUCTORS are arranged so their
 * typical alignment matches.
 * A cacheline is typical/always less than a PAGE_SIZE so
 * the sections that has this restriction (or similar)
 * is located before the ones requiring PAGE_SIZE alignment.
 * NOSAVE_DATA starts and ends with a PAGE_SIZE alignment which
 * matches the requirement of PAGE_ALIGNED_DATA.
 *
 * use 0 as page_align if page_aligned data is not used */
#define RW_DATA(cacheline, pagealigned, inittask) \
    . = ALIGN(PAGE_SIZE); \
    .data : AT(ADDR(.data) - LOAD_OFFSET) { \
        INIT_TASK_DATA(inittask) \
        DATA_DATA \
    }

#define JUMP_TABLE_DATA         \
    . = ALIGN(8);               \
    __start___jump_table = .;   \
    KEEP(*(__jump_table))       \
    __stop___jump_table = .;

/*
 * Allow architectures to handle ro_after_init data on their
 * own by defining an empty RO_AFTER_INIT_DATA.
 */
#ifndef RO_AFTER_INIT_DATA
#define RO_AFTER_INIT_DATA      \
    . = ALIGN(8);               \
    __start_ro_after_init = .;  \
    *(.data..ro_after_init)     \
    JUMP_TABLE_DATA             \
    __end_ro_after_init = .;
#endif

/*
 * Read only Data
 */
#define RO_DATA(align)  \
    . = ALIGN((align)); \
    .rodata : AT(ADDR(.rodata) - LOAD_OFFSET) { \
        __start_rodata = .;     \
        *(.rodata) *(.rodata.*) \
        RO_AFTER_INIT_DATA  /* Read only after init */  \
        . = ALIGN(8); \
    }   \
        \
    /* Kernel symbol table: Normal symbols */ \
    __ksymtab : AT(ADDR(__ksymtab) - LOAD_OFFSET) { \
        __start___ksymtab = .;                  \
        KEEP(*(SORT(___ksymtab+*)))             \
        __stop___ksymtab = .;                   \
    }                               \
                                    \
    /* Kernel symbol table: GPL-only symbols */         \
    __ksymtab_gpl : AT(ADDR(__ksymtab_gpl) - LOAD_OFFSET) { \
        __start___ksymtab_gpl = .;      \
        KEEP(*(SORT(___ksymtab_gpl+*))) \
        __stop___ksymtab_gpl = .;       \
    }                                   \
                                        \
    /* Kernel symbol table: strings */  \
    __ksymtab_strings : AT(ADDR(__ksymtab_strings) - LOAD_OFFSET) { \
        *(__ksymtab_strings)                    \
    } \
    . = ALIGN((align)); \
    __end_rodata = .;

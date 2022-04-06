/*
 * Helper macros to support writing architecture specific
 * linker scripts.
 */

#ifndef LOAD_OFFSET
#define LOAD_OFFSET 0
#endif

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

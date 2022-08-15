// SPDX-License-Identifier: GPL-2.0-only
/*
 * linux/fs/binfmt_elf.c
 *
 * These are the functions used to load ELF format executables as used
 * on SVr4 machines.  Information on the format may be found in the book
 * "UNIX SYSTEM V RELEASE 4 Programmers Guide: Ansi C and Programming Support
 * Tools".
 *
 * Copyright 1993, 1994: Eric Youngdale (ericy@cais.com).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/log2.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/binfmts.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/personality.h>
#if 0
#include <linux/elfcore.h>
#endif
#include <linux/init.h>
//#include <linux/highuid.h>
#include <linux/compiler.h>
#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>
//#include <linux/security.h>
#include <linux/random.h>
#include <linux/elf.h>
#if 0
#include <linux/elf-randomize.h>
#include <linux/utsname.h>
#include <linux/coredump.h>
#endif
#include <linux/sched.h>
#include <linux/sched/coredump.h>
#include <linux/sched/task_stack.h>
//#include <linux/sched/cputime.h>
#include <linux/sizes.h>
#include <linux/types.h>
#include <linux/cred.h>
//#include <linux/dax.h>
#include <linux/uaccess.h>
#include <asm/param.h>
#include <asm/page.h>

/**
 * struct arch_elf_state - arch-specific ELF loading state
 *
 * This structure is used to preserve architecture specific data during
 * the loading of an ELF file, throughout the checking of architecture
 * specific ELF headers & through to the point where the ELF load is
 * known to be proceeding (ie. SET_PERSONALITY).
 *
 * This implementation is a dummy for architectures which require no
 * specific state.
 */
struct arch_elf_state {
};

#define INIT_ARCH_ELF_STATE {}

/* That's for binfmt_elf_fdpic to deal with */
#ifndef elf_check_fdpic
#define elf_check_fdpic(ex) false
#endif

#if ELF_EXEC_PAGESIZE > PAGE_SIZE
#define ELF_MIN_ALIGN   ELF_EXEC_PAGESIZE
#else
#define ELF_MIN_ALIGN   PAGE_SIZE
#endif

#define ELF_PAGESTART(_v) ((_v) & ~(int)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1))

#define BAD_ADDR(x) (unlikely((unsigned long)(x) >= TASK_SIZE))

static int elf_read(struct file *file, void *buf, size_t len,
                    loff_t pos)
{
    ssize_t rv;

    rv = kernel_read(file, buf, len, &pos);
    if (unlikely(rv != len)) {
        return (rv < 0) ? rv : -EIO;
    }
    return 0;
}

/**
 * load_elf_phdrs() - load ELF program headers
 * @elf_ex:   ELF header of the binary whose program headers should be loaded
 * @elf_file: the opened ELF binary file
 *
 * Loads ELF program headers from the binary file elf_file, which has the ELF
 * header pointed to by elf_ex, into a newly allocated array. The caller is
 * responsible for freeing the allocated data. Returns an ERR_PTR upon failure.
 */
static struct elf_phdr *
load_elf_phdrs(const struct elfhdr *elf_ex, struct file *elf_file)
{
    struct elf_phdr *elf_phdata = NULL;
    int retval, err = -1;
    unsigned int size;

    /*
     * If the size of this structure has changed, then punt, since
     * we will be doing the wrong thing.
     */
    if (elf_ex->e_phentsize != sizeof(struct elf_phdr))
        goto out;

    /* Sanity check the number of program headers... */
    /* ...and their total size. */
    size = sizeof(struct elf_phdr) * elf_ex->e_phnum;
    if (size == 0 || size > 65536 || size > ELF_MIN_ALIGN)
        goto out;

    elf_phdata = kmalloc(size, GFP_KERNEL);
    if (!elf_phdata)
        goto out;

    /* Read in the program headers */
    retval = elf_read(elf_file, elf_phdata, size, elf_ex->e_phoff);
    if (retval < 0) {
        err = retval;
        goto out;
    }

    /* Success! */
    err = 0;
 out:
    if (err) {
        kfree(elf_phdata);
        elf_phdata = NULL;
    }
    return elf_phdata;
}

#define NOTE_DATA_SZ SZ_1K
#define GNU_PROPERTY_TYPE_0_NAME "GNU"
#define NOTE_NAME_SZ (sizeof(GNU_PROPERTY_TYPE_0_NAME))

static int parse_elf_properties(struct file *f,
                                const struct elf_phdr *phdr,
                                struct arch_elf_state *arch)
{
    return 0;
}

static int set_brk(unsigned long start, unsigned long end, int prot)
{
    start = ELF_PAGEALIGN(start);
    end = ELF_PAGEALIGN(end);
    if (end > start) {
        /*
         * Map the last of the bss segment.
         * If the header is requesting these pages to be
         * executable, honour that (ppc32 needs this).
         */
        int error = vm_brk_flags(start, end - start,
                                 prot & PROT_EXEC ? VM_EXEC : 0);
        if (error)
            return error;
    }
    current->mm->start_brk = current->mm->brk = end;
    return 0;
}

static inline int make_prot(u32 p_flags, struct arch_elf_state *arch_state,
                            bool has_interp, bool is_interp)
{
    int prot = 0;

    if (p_flags & PF_R)
        prot |= PROT_READ;
    if (p_flags & PF_W)
        prot |= PROT_WRITE;
    if (p_flags & PF_X)
        prot |= PROT_EXEC;

    return arch_elf_adjust_prot(prot, arch_state, has_interp, is_interp);
}

static unsigned long elf_map(struct file *filep, unsigned long addr,
                             const struct elf_phdr *eppnt, int prot, int type,
                             unsigned long total_size)
{
    unsigned long map_addr;
    unsigned long size = eppnt->p_filesz + ELF_PAGEOFFSET(eppnt->p_vaddr);
    unsigned long off = eppnt->p_offset - ELF_PAGEOFFSET(eppnt->p_vaddr);
    addr = ELF_PAGESTART(addr);
    size = ELF_PAGEALIGN(size);

    /* mmap() will return -EINVAL if given a zero size, but a
     * segment with zero filesize is perfectly valid */
    if (!size)
        return addr;

    /*
    * total_size is the size of the ELF (interpreter) image.
    * The _first_ mmap needs to know the full size, otherwise
    * randomization might put this image into an overlapping
    * position with the ELF binary image. (since size < total_size)
    * So we first map the 'big' image - and unmap the remainder at
    * the end. (which unmap is needed for ELF images with holes.)
    */
    if (total_size) {
        total_size = ELF_PAGEALIGN(total_size);
        map_addr = vm_mmap(filep, addr, total_size, prot, type, off);
        if (!BAD_ADDR(map_addr))
            vm_munmap(map_addr+size, total_size-size);
    } else
        map_addr = vm_mmap(filep, addr, size, prot, type, off);

    if ((type & MAP_FIXED_NOREPLACE) &&
        PTR_ERR((void *)map_addr) == -EEXIST)
        pr_info("%d (%s): Uhuuh, elf segment at %px requested "
                "but the memory is mapped already\n",
                task_pid_nr(current), current->comm, (void *)addr);

    return(map_addr);
}

/* We need to explicitly zero any fractional pages
   after the data section (i.e. bss).  This would
   contain the junk from the file that should not
   be in memory
 */
static int padzero(unsigned long elf_bss)
{
    unsigned long nbyte;

    nbyte = ELF_PAGEOFFSET(elf_bss);
    if (nbyte) {
        nbyte = ELF_MIN_ALIGN - nbyte;
        printk("%s: step1 (%x)(%x)\n", __func__, elf_bss, nbyte);
        if (clear_user((void __user *) elf_bss, nbyte))
            return -EFAULT;
    }
    return 0;
}

static int load_elf_binary(struct linux_binprm *bprm)
{
    struct file *interpreter = NULL; /* to shut gcc up */
    unsigned long load_bias = 0, phdr_addr = 0;
    int first_pt_load = 1;
    unsigned long error;
    struct elf_phdr *elf_ppnt, *elf_phdata, *interp_elf_phdata = NULL;
    struct elf_phdr *elf_property_phdata = NULL;
    unsigned long elf_bss, elf_brk;
    int bss_prot = 0;
    int retval, i;
    unsigned long elf_entry;
    unsigned long e_entry;
    unsigned long interp_load_addr = 0;
    unsigned long start_code, end_code, start_data, end_data;
    unsigned long reloc_func_desc __maybe_unused = 0;
    int executable_stack = EXSTACK_DEFAULT;
    struct elfhdr *elf_ex = (struct elfhdr *)bprm->buf;
    struct elfhdr *interp_elf_ex = NULL;
    struct arch_elf_state arch_state = INIT_ARCH_ELF_STATE;
    struct mm_struct *mm;
    struct pt_regs *regs;

    retval = -ENOEXEC;
    /* First of all, some simple consistency checks */
    if (memcmp(elf_ex->e_ident, ELFMAG, SELFMAG) != 0)
        goto out;

    if (elf_ex->e_type != ET_EXEC && elf_ex->e_type != ET_DYN)
        goto out;
    if (!elf_check_arch(elf_ex))
        goto out;
    if (elf_check_fdpic(elf_ex))
        goto out;
    if (!bprm->file->f_op->mmap)
        goto out;

    elf_phdata = load_elf_phdrs(elf_ex, bprm->file);
    if (!elf_phdata)
        goto out;

    elf_ppnt = elf_phdata;
    for (i = 0; i < elf_ex->e_phnum; i++, elf_ppnt++) {
        char *elf_interpreter;

        if (elf_ppnt->p_type == PT_GNU_PROPERTY) {
            elf_property_phdata = elf_ppnt;
            continue;
        }

        if (elf_ppnt->p_type != PT_INTERP)
            continue;

        panic("%s: 1 [%d]!\n", __func__, i);
    }

    elf_ppnt = elf_phdata;
    for (i = 0; i < elf_ex->e_phnum; i++, elf_ppnt++) {
        switch (elf_ppnt->p_type) {
        case PT_GNU_STACK:
            if (elf_ppnt->p_flags & PF_X)
                executable_stack = EXSTACK_ENABLE_X;
            else
                executable_stack = EXSTACK_DISABLE_X;
            break;

        case PT_LOPROC ... PT_HIPROC:
            break;
        }
    }

    /* Some simple consistency checks for the interpreter */
    if (interpreter) {
        panic("%s: interpreter!\n", __func__);
    }

    retval = parse_elf_properties(interpreter ?: bprm->file,
                                  elf_property_phdata, &arch_state);
    if (retval)
        goto out_free_dentry;

    /* Flush all traces of the currently running executable */
    retval = begin_new_exec(bprm);
    if (retval)
        goto out_free_dentry;

    /* Do this immediately, since STACK_TOP as used in setup_arg_pages
       may depend on the personality.  */
    SET_PERSONALITY2(*elf_ex, &arch_state);

    if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
        current->flags |= PF_RANDOMIZE;

    setup_new_exec(bprm);

    /* Do this so that we can load the interpreter, if need be.  We will
       change some of these later */
    retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
                             executable_stack);
    if (retval < 0)
        goto out_free_dentry;

    elf_bss = 0;
    elf_brk = 0;

    start_code = ~0UL;
    end_code = 0;
    start_data = 0;
    end_data = 0;

    /* Now we do a little grungy work by mmapping the ELF image into
       the correct location in memory. */
    for(i = 0, elf_ppnt = elf_phdata; i < elf_ex->e_phnum; i++, elf_ppnt++) {
        int elf_prot, elf_flags;
        unsigned long k, vaddr;
        unsigned long total_size = 0;
        unsigned long alignment;

        if (elf_ppnt->p_type != PT_LOAD)
            continue;

        if (unlikely(elf_brk > elf_bss)) {
            unsigned long nbyte;

            /* There was a PT_LOAD segment with p_memsz > p_filesz
               before this one. Map anonymous pages, if needed,
               and clear the area.  */
            retval = set_brk(elf_bss + load_bias,
                             elf_brk + load_bias, bss_prot);
            if (retval)
                goto out_free_dentry;
            nbyte = ELF_PAGEOFFSET(elf_bss);
            if (nbyte) {
                nbyte = ELF_MIN_ALIGN - nbyte;
                if (nbyte > elf_brk - elf_bss)
                    nbyte = elf_brk - elf_bss;
                if (clear_user((void __user *)elf_bss + load_bias, nbyte)) {
                    /*
                     * This bss-zeroing can fail if the ELF
                     * file specifies odd protections. So
                     * we don't check the return value
                     */
                }
                panic("%s: 0!\n", __func__);
            }

            panic("%s: (elf_brk > elf_bss)!\n", __func__);
        }

        elf_prot = make_prot(elf_ppnt->p_flags, &arch_state,
                             !!interpreter, false);

        elf_flags = MAP_PRIVATE;

        vaddr = elf_ppnt->p_vaddr;
        /*
         * The first time through the loop, first_pt_load is true:
         * layout will be calculated. Once set, use MAP_FIXED since
         * we know we've already safely mapped the entire region with
         * MAP_FIXED_NOREPLACE in the once-per-binary logic following.
         */
        if (!first_pt_load) {
            elf_flags |= MAP_FIXED;
        } else if (elf_ex->e_type == ET_EXEC) {
            /*
             * This logic is run once for the first LOAD Program
             * Header for ET_EXEC binaries. No special handling
             * is needed.
             */
            elf_flags |= MAP_FIXED_NOREPLACE;
        } else if (elf_ex->e_type == ET_DYN) {
            panic("%s: ET_DYN!\n", __func__);
        }

        error = elf_map(bprm->file, load_bias + vaddr, elf_ppnt,
                        elf_prot, elf_flags, total_size);
        if (BAD_ADDR(error)) {
            retval = IS_ERR((void *)error) ?  PTR_ERR((void*)error) : -EINVAL;
            goto out_free_dentry;
        }

        if (first_pt_load) {
            first_pt_load = 0;
            if (elf_ex->e_type == ET_DYN) {
                load_bias += error - ELF_PAGESTART(load_bias + vaddr);
                reloc_func_desc = load_bias;
            }
        }

        /*
         * Figure out which segment in the file contains the Program
         * Header table, and map to the associated memory address.
         */
        if (elf_ppnt->p_offset <= elf_ex->e_phoff &&
            elf_ex->e_phoff < elf_ppnt->p_offset + elf_ppnt->p_filesz) {
            phdr_addr = elf_ex->e_phoff - elf_ppnt->p_offset +
                elf_ppnt->p_vaddr;
        }

        k = elf_ppnt->p_vaddr;
        if ((elf_ppnt->p_flags & PF_X) && k < start_code)
            start_code = k;
        if (start_data < k)
            start_data = k;

        /*
         * Check to see if the section's size will overflow the
         * allowed task size. Note that p_filesz must always be
         * <= p_memsz so it is only necessary to check p_memsz.
         */
        if (BAD_ADDR(k) || elf_ppnt->p_filesz > elf_ppnt->p_memsz ||
            elf_ppnt->p_memsz > TASK_SIZE ||
            TASK_SIZE - elf_ppnt->p_memsz < k) {
            /* set_brk can never work. Avoid overflows. */
            retval = -EINVAL;
            goto out_free_dentry;
        }

        k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;

        if (k > elf_bss)
            elf_bss = k;
        if ((elf_ppnt->p_flags & PF_X) && end_code < k)
            end_code = k;
        if (end_data < k)
            end_data = k;
        k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
        if (k > elf_brk) {
            bss_prot = elf_prot;
            elf_brk = k;
        }
    }

    e_entry = elf_ex->e_entry + load_bias;
    phdr_addr += load_bias;
    elf_bss += load_bias;
    elf_brk += load_bias;
    start_code += load_bias;
    end_code += load_bias;
    start_data += load_bias;
    end_data += load_bias;

    /* Calling set_brk effectively mmaps the pages that we need
     * for the bss and break sections.  We must do this before
     * mapping in the interpreter, to make sure it doesn't wind
     * up getting placed where the bss needs to go.
     */
    retval = set_brk(elf_bss, elf_brk, bss_prot);
    if (retval)
        goto out_free_dentry;
    if (likely(elf_bss != elf_brk) && unlikely(padzero(elf_bss))) {
        retval = -EFAULT; /* Nobody gets to see this, but.. */
        goto out_free_dentry;
    }

    panic("%s: END!\n", __func__);

 out:
    return retval;

    /* error cleanup */
 out_free_dentry:
    kfree(interp_elf_ex);
    kfree(interp_elf_phdata);
    allow_write_access(interpreter);
    if (interpreter)
        fput(interpreter);
 out_free_ph:
    kfree(elf_phdata);
    goto out;
}

#define load_elf_library NULL

static struct linux_binfmt elf_format = {
    .module         = THIS_MODULE,
    .load_binary    = load_elf_binary,
    .load_shlib     = load_elf_library,
#if 0
    .core_dump      = elf_core_dump,
    .min_coredump   = ELF_EXEC_PAGESIZE,
#endif
};

static int __init init_elf_binfmt(void)
{
    register_binfmt(&elf_format);
    return 0;
}

static void __exit exit_elf_binfmt(void)
{
    /* Remove the COFF and ELF loaders. */
    unregister_binfmt(&elf_format);
}

core_initcall(init_elf_binfmt);
module_exit(exit_elf_binfmt);

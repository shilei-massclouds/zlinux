/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BINFMTS_H
#define _LINUX_BINFMTS_H

#include <linux/sched.h>
#if 0
#include <linux/unistd.h>
#include <asm/exec.h>
#endif
#include <uapi/linux/binfmts.h>

struct filename;
struct coredump_params;

#define CORENAME_MAX_SIZE 128

/*
 * This structure is used to hold the arguments that are used when loading binaries.
 */
struct linux_binprm {
    struct vm_area_struct *vma;
    unsigned long vma_pages;

    struct mm_struct *mm;
    unsigned long p; /* current top of mem */
    unsigned long argmin; /* rlimit marker for copy_strings() */
    unsigned int
        /* Should an execfd be passed to userspace? */
        have_execfd:1,

        /* Use the creds of a script (see binfmt_misc) */
        execfd_creds:1,
        /*
         * Set by bprm_creds_for_exec hook to indicate a
         * privilege-gaining exec has happened. Used to set
         * AT_SECURE auxv for glibc.
         */
        secureexec:1,
        /*
         * Set when errors can no longer be returned to the
         * original userspace.
         */
        point_of_no_return:1;

    struct file *executable;    /* Executable to pass to the interpreter */
    struct file *interpreter;
    struct file *file;
    struct cred *cred;          /* new credentials */
    int unsafe;     /* how unsafe this exec is (mask of LSM_UNSAFE_*) */
    unsigned int per_clear;     /* bits to clear in current->personality */
    int argc, envc;
    const char *filename;       /* Name of binary as seen by procps */
    const char *interp;         /* Name of the binary really executed. Most
                                   of the time same as filename, but could be
                                   different for binfmt_{misc,script} */
    const char *fdpath;         /* generated filename for execveat */
    unsigned interp_flags;
    int execfd;                 /* File descriptor of the executable */
    unsigned long loader, exec;

    struct rlimit rlim_stack;   /* Saved RLIMIT_STACK used during exec. */

    char buf[BINPRM_BUF_SIZE];
} __randomize_layout;

int kernel_execve(const char *filename,
                  const char *const *argv, const char *const *envp);

#endif /* _LINUX_BINFMTS_H */

// SPDX-License-Identifier: GPL-2.0-only

#include <linux/export.h>
#if 0
#include <linux/nsproxy.h>
#endif
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/user_namespace.h>
#if 0
#include <linux/proc_ns.h>
#include <linux/highuid.h>
#endif
#include <linux/cred.h>
#if 0
#include <linux/securebits.h>
#include <linux/keyctl.h>
#include <linux/key-type.h>
#include <keys/user-type.h>
#include <linux/seq_file.h>
#endif
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ctype.h>
#if 0
#include <linux/projid.h>
#include <linux/fs_struct.h>
#include <linux/bsearch.h>
#include <linux/sort.h>
#endif

void __put_user_ns(struct user_namespace *ns)
{
    panic("%s: END!\n", __func__);
    //schedule_work(&ns->work);
}
EXPORT_SYMBOL(__put_user_ns);

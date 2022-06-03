// SPDX-License-Identifier: GPL-2.0
#include <linux/mm_types.h>

/*
 * For dynamically allocated mm_structs, there is a dynamically sized cpumask
 * at the end of the structure, the size of which depends on the maximum CPU
 * number the system can see. That way we allocate only as much memory for
 * mm_cpumask() as needed for the hundreds, or thousands of processes that
 * a system typically runs.
 *
 * Since there is only one init_mm in the entire system, keep it simple
 * and size this cpu_bitmask to NR_CPUS.
 */
struct mm_struct init_mm = {
};

void setup_initial_init_mm(void *start_code, void *end_code,
                           void *end_data, void *brk)
{
    init_mm.start_code = (unsigned long)start_code;
    init_mm.end_code = (unsigned long)end_code;
    init_mm.end_data = (unsigned long)end_data;
    init_mm.brk = (unsigned long)brk;
}

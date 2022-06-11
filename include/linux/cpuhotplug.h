/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __CPUHOTPLUG_H
#define __CPUHOTPLUG_H

#include <linux/types.h>

/*
 * CPU hotplug states. The state machine invokes the installed state
 * startup callbacks sequentially from CPUHP_OFFLINE + 1 to CPUHP_ONLINE
 * during a CPU online operation. During a CPU offline operation the
 * installed teardown callbacks are invoked in the reverse order from
 * CPU_ONLINE - 1 down to CPUHP_OFFLINE.
 *
 * The state space has three sections: PREPARE, STARTING and ONLINE.
 *
 * PREPARE: The callbacks are invoked on a control CPU before the
 * hotplugged CPU is started up or after the hotplugged CPU has died.
 *
 * STARTING: The callbacks are invoked on the hotplugged CPU from the low level
 * hotplug startup/teardown code with interrupts disabled.
 *
 * ONLINE: The callbacks are invoked on the hotplugged CPU from the per CPU
 * hotplug thread with interrupts and preemption enabled.
 *
 * Adding explicit states to this enum is only necessary when:
 *
 * 1) The state is within the STARTING section
 *
 * 2) The state has ordering constraints vs. other states in the
 *    same section.
 *
 * If neither #1 nor #2 apply, please use the dynamic state space when
 * setting up a state by using CPUHP_PREPARE_DYN or CPUHP_PREPARE_ONLINE
 * for the @state argument of the setup function.
 *
 * See Documentation/core-api/cpu_hotplug.rst for further information and
 * examples.
 */
enum cpuhp_state {
    CPUHP_INVALID = -1,
    CPUHP_ONLINE,
};

#endif /* __CPUHOTPLUG_H */

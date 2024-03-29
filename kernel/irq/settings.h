/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Internal header to deal with irq_desc->status which will be renamed
 * to irq_desc->settings.
 */
enum {
    _IRQ_DEFAULT_INIT_FLAGS = IRQ_DEFAULT_INIT_FLAGS,
    _IRQ_PER_CPU        = IRQ_PER_CPU,
    _IRQ_LEVEL          = IRQ_LEVEL,
    _IRQ_NOPROBE        = IRQ_NOPROBE,
    _IRQ_NOREQUEST      = IRQ_NOREQUEST,
    _IRQ_NOTHREAD       = IRQ_NOTHREAD,
    _IRQ_NOAUTOEN       = IRQ_NOAUTOEN,
    _IRQ_MOVE_PCNTXT    = IRQ_MOVE_PCNTXT,
    _IRQ_NO_BALANCING   = IRQ_NO_BALANCING,
    _IRQ_NESTED_THREAD  = IRQ_NESTED_THREAD,
    _IRQ_PER_CPU_DEVID  = IRQ_PER_CPU_DEVID,
    _IRQ_IS_POLLED      = IRQ_IS_POLLED,
    _IRQ_DISABLE_UNLAZY = IRQ_DISABLE_UNLAZY,
    _IRQ_HIDDEN         = IRQ_HIDDEN,
    _IRQ_NO_DEBUG       = IRQ_NO_DEBUG,
    _IRQF_MODIFY_MASK   = IRQF_MODIFY_MASK,
};

static inline void
irq_settings_clr_and_set(struct irq_desc *desc, u32 clr, u32 set)
{
    desc->status_use_accessors &= ~(clr & _IRQF_MODIFY_MASK);
    desc->status_use_accessors |= (set & _IRQF_MODIFY_MASK);
}

static inline bool irq_settings_is_per_cpu_devid(struct irq_desc *desc)
{
    return desc->status_use_accessors & _IRQ_PER_CPU_DEVID;
}

static inline bool irq_settings_has_no_balance_set(struct irq_desc *desc)
{
    return desc->status_use_accessors & _IRQ_NO_BALANCING;
}

static inline bool irq_settings_is_per_cpu(struct irq_desc *desc)
{
    return desc->status_use_accessors & _IRQ_PER_CPU;
}

static inline bool irq_settings_can_move_pcntxt(struct irq_desc *desc)
{
    return desc->status_use_accessors & _IRQ_MOVE_PCNTXT;
}

static inline u32 irq_settings_get_trigger_mask(struct irq_desc *desc)
{
    return desc->status_use_accessors & IRQ_TYPE_SENSE_MASK;
}

static inline void irq_settings_set_nothread(struct irq_desc *desc)
{
    desc->status_use_accessors |= _IRQ_NOTHREAD;
}

static inline void irq_settings_set_norequest(struct irq_desc *desc)
{
    desc->status_use_accessors |= _IRQ_NOREQUEST;
}

static inline void irq_settings_clr_noprobe(struct irq_desc *desc)
{
    desc->status_use_accessors &= ~_IRQ_NOPROBE;
}

static inline void irq_settings_set_noprobe(struct irq_desc *desc)
{
    desc->status_use_accessors |= _IRQ_NOPROBE;
}

static inline void
irq_settings_set_trigger_mask(struct irq_desc *desc, u32 mask)
{
    desc->status_use_accessors &= ~IRQ_TYPE_SENSE_MASK;
    desc->status_use_accessors |= mask & IRQ_TYPE_SENSE_MASK;
}

static inline bool irq_settings_is_level(struct irq_desc *desc)
{
    return desc->status_use_accessors & _IRQ_LEVEL;
}

static inline void irq_settings_clr_level(struct irq_desc *desc)
{
    desc->status_use_accessors &= ~_IRQ_LEVEL;
}

static inline void irq_settings_set_level(struct irq_desc *desc)
{
    desc->status_use_accessors |= _IRQ_LEVEL;
}

static inline bool irq_settings_can_request(struct irq_desc *desc)
{
    return !(desc->status_use_accessors & _IRQ_NOREQUEST);
}

static inline bool irq_settings_is_nested_thread(struct irq_desc *desc)
{
    return desc->status_use_accessors & _IRQ_NESTED_THREAD;
}

static inline bool irq_settings_can_thread(struct irq_desc *desc)
{
    return !(desc->status_use_accessors & _IRQ_NOTHREAD);
}

static inline void irq_settings_set_no_debug(struct irq_desc *desc)
{
    desc->status_use_accessors |= _IRQ_NO_DEBUG;
}

static inline void irq_settings_set_no_balancing(struct irq_desc *desc)
{
    desc->status_use_accessors |= _IRQ_NO_BALANCING;
}

static inline bool irq_settings_can_autoenable(struct irq_desc *desc)
{
    return !(desc->status_use_accessors & _IRQ_NOAUTOEN);
}

static inline bool irq_settings_no_debug(struct irq_desc *desc)
{
    return desc->status_use_accessors & _IRQ_NO_DEBUG;
}

static inline void irq_settings_set_per_cpu(struct irq_desc *desc)
{
    desc->status_use_accessors |= _IRQ_PER_CPU;
}

static inline bool irq_settings_disable_unlazy(struct irq_desc *desc)
{
    return desc->status_use_accessors & _IRQ_DISABLE_UNLAZY;
}

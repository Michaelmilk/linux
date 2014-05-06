#ifndef LINUX_PREEMPT_MASK_H
#define LINUX_PREEMPT_MASK_H

#include <linux/preempt.h>

/*
 * We put the hardirq and softirq counter into the preemption
 * counter. The bitmask has the following meaning:
 *
 * - bits 0-7 are the preemption count (max preemption depth: 256)
 * - bits 8-15 are the softirq count (max # of softirqs: 256)
 *
 * The hardirq count could in theory be the same as the number of
 * interrupts in the system, but we run all interrupt handlers with
 * interrupts disabled, so we cannot have nesting interrupts. Though
 * there are a few palaeontologic drivers which reenable interrupts in
 * the handler, so we need more than one bit here.
 *
 * PREEMPT_MASK:	0x000000ff
 * SOFTIRQ_MASK:	0x0000ff00
 * HARDIRQ_MASK:	0x000f0000
 *     NMI_MASK:	0x00100000
 * PREEMPT_ACTIVE:	0x00200000
 */

/*
硬中断和软中断计数器保存在抢占计数器字段preempt_count中
*/

/* 进程抢占占8个bit，0-7 */
#define PREEMPT_BITS	8
/* 软中断占8个bit，8-15 */
#define SOFTIRQ_BITS	8
#define HARDIRQ_BITS	4
/* 不可屏蔽中断占1个bit，26 */
#define NMI_BITS	1

#define PREEMPT_SHIFT	0
/* 0 + 8 = 8 */
#define SOFTIRQ_SHIFT	(PREEMPT_SHIFT + PREEMPT_BITS)
/* 8 + 8 = 16 */
#define HARDIRQ_SHIFT	(SOFTIRQ_SHIFT + SOFTIRQ_BITS)
/* 16 + 4 = 20 */
#define NMI_SHIFT	(HARDIRQ_SHIFT + HARDIRQ_BITS)

#define __IRQ_MASK(x)	((1UL << (x))-1)

/* PREEMPT_MASK: 0x000000ff */
#define PREEMPT_MASK	(__IRQ_MASK(PREEMPT_BITS) << PREEMPT_SHIFT)
/* SOFTIRQ_MASK: 0x0000ff00 */
#define SOFTIRQ_MASK	(__IRQ_MASK(SOFTIRQ_BITS) << SOFTIRQ_SHIFT)
/* HARDIRQ_MASK: 0x000f0000 */
#define HARDIRQ_MASK	(__IRQ_MASK(HARDIRQ_BITS) << HARDIRQ_SHIFT)
/* NMI_MASK: 0x00100000 */
#define NMI_MASK	(__IRQ_MASK(NMI_BITS)     << NMI_SHIFT)

#define PREEMPT_OFFSET	(1UL << PREEMPT_SHIFT)
#define SOFTIRQ_OFFSET	(1UL << SOFTIRQ_SHIFT)
#define HARDIRQ_OFFSET	(1UL << HARDIRQ_SHIFT)
#define NMI_OFFSET	(1UL << NMI_SHIFT)

#define SOFTIRQ_DISABLE_OFFSET	(2 * SOFTIRQ_OFFSET)

#define PREEMPT_ACTIVE_BITS	1
#define PREEMPT_ACTIVE_SHIFT	(NMI_SHIFT + NMI_BITS)
#define PREEMPT_ACTIVE	(__IRQ_MASK(PREEMPT_ACTIVE_BITS) << PREEMPT_ACTIVE_SHIFT)

#define hardirq_count()	(preempt_count() & HARDIRQ_MASK)
#define softirq_count()	(preempt_count() & SOFTIRQ_MASK)
#define irq_count()	(preempt_count() & (HARDIRQ_MASK | SOFTIRQ_MASK \
				 | NMI_MASK))

/*
 * Are we doing bottom half or hardware interrupt processing?
 * Are we in a softirq context? Interrupt context?
 * in_softirq - Are we currently processing softirq or have bh disabled?
 * in_serving_softirq - Are we currently processing softirq?
 */

/* 硬中断 */
#define in_irq()		(hardirq_count())
/* 软中断 */
#define in_softirq()		(softirq_count())
/* 硬中断 软中断 不可屏蔽中断 */
#define in_interrupt()		(irq_count())
#define in_serving_softirq()	(softirq_count() & SOFTIRQ_OFFSET)

/*
 * Are we in NMI context?
 */
#define in_nmi()	(preempt_count() & NMI_MASK)

#if defined(CONFIG_PREEMPT_COUNT)
# define PREEMPT_CHECK_OFFSET 1
#else
# define PREEMPT_CHECK_OFFSET 0
#endif

/*
 * The preempt_count offset needed for things like:
 *
 *  spin_lock_bh()
 *
 * Which need to disable both preemption (CONFIG_PREEMPT_COUNT) and
 * softirqs, such that unlock sequences of:
 *
 *  spin_unlock();
 *  local_bh_enable();
 *
 * Work as expected.
 */
#define SOFTIRQ_LOCK_OFFSET (SOFTIRQ_DISABLE_OFFSET + PREEMPT_CHECK_OFFSET)

/*
 * Are we running in atomic context?  WARNING: this macro cannot
 * always detect atomic context; in particular, it cannot know about
 * held spinlocks in non-preemptible kernels.  Thus it should not be
 * used in the general case to determine whether sleeping is possible.
 * Do not use in_atomic() in driver code.
 */
#define in_atomic()	((preempt_count() & ~PREEMPT_ACTIVE) != 0)

/*
 * Check whether we were atomic before we did preempt_disable():
 * (used by the scheduler, *after* releasing the kernel lock)
 */
#define in_atomic_preempt_off() \
		((preempt_count() & ~PREEMPT_ACTIVE) != PREEMPT_CHECK_OFFSET)

#ifdef CONFIG_PREEMPT_COUNT
# define preemptible()	(preempt_count() == 0 && !irqs_disabled())
#else
# define preemptible()	0
#endif

#endif /* LINUX_PREEMPT_MASK_H */

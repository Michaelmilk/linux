/*
 * 8253/PIT functions
 *
 */
#include <linux/clockchips.h>
#include <linux/module.h>
#include <linux/timex.h>
#include <linux/i8253.h>

#include <asm/hpet.h>
#include <asm/time.h>
#include <asm/smp.h>

/*
 * HPET replaces the PIT, when enabled. So we need to know, which of
 * the two timers is used
 */
/*
指向系统当前使用的clock_event_device
*/
struct clock_event_device *global_clock_event;

/*
 * Initialize the conversion factor and the min/max deltas of the clock event
 * structure and register the clock event source with the framework.
 */
/*
初始化8253芯片
*/
void __init setup_pit_timer(void)
{
	clockevent_i8253_init(true);
	global_clock_event = &i8253_clockevent;
}

#ifndef CONFIG_X86_64
static int __init init_pit_clocksource(void)
{
	 /*
	  * Several reasons not to register PIT as a clocksource:
	  *
	  * - On SMP PIT does not scale due to i8253_lock
	  * - when HPET is enabled
	  * - when local APIC timer is active (PIT is switched off)
	  */
	if (num_possible_cpus() > 1 || is_hpet_enabled() ||
	    i8253_clockevent.mode != CLOCK_EVT_MODE_PERIODIC)
		return 0;

	return clocksource_i8253_init();
}
arch_initcall(init_pit_clocksource);
#endif /* !CONFIG_X86_64 */

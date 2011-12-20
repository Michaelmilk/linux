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
/*
PIT : programmable interval timer 可编程间隔定时器
*/
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

/*
intel8253是NMOS工艺制成的可编程计数器/定时器，有几种芯片型号，
外形引脚及功能都是兼容的，只是工作的最高计数速率有所差异，例如8253（2.6MHz）,8253-5(5MHz) 
8253内部有三个计数器，分别成为计数器0、计数器1和计数器2，他们的机构完全相同。
每个计数器的输入和输出都决定于设置在控制寄存器中的控制字，互相之间工作完全独立。
每个计数器通过三个引脚和外部联系，
一个为时钟输入端CLK，一个为门控信号输入端GATE，另一个为输出端OUT。
每个计数器内部有一个8位的控制寄存器，
还有一个16位的计数初值寄存器CR、一个计数执行部件CE和一个输出锁存器OL。
执行部件实际上是一个16位的减法计数器，
它的起始值就是初值寄存器的值，而初始值寄存器的值是通过程序设置的。
输出锁存器的值是通过程序设置的。
输出锁存器OL用来锁存计数执行部件CE的内容，从而使CPU可以对此进行读操作。
顺便提一下，CR、CE和OL都是16位寄存器，但是也可以作8位寄存器来用。
*/


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
ָ��ϵͳ��ǰʹ�õ�clock_event_device
*/
struct clock_event_device *global_clock_event;

/*
 * Initialize the conversion factor and the min/max deltas of the clock event
 * structure and register the clock event source with the framework.
 */
/*
��ʼ��8253оƬ
*/
void __init setup_pit_timer(void)
{
	clockevent_i8253_init(true);
	global_clock_event = &i8253_clockevent;
}

#ifndef CONFIG_X86_64
/*
PIT : programmable interval timer �ɱ�̼����ʱ��
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
intel8253��NMOS�����ƳɵĿɱ�̼�����/��ʱ�����м���оƬ�ͺţ�
�������ż����ܶ��Ǽ��ݵģ�ֻ�ǹ�������߼��������������죬����8253��2.6MHz��,8253-5(5MHz) 
8253�ڲ����������������ֱ��Ϊ������0��������1�ͼ�����2�����ǵĻ�����ȫ��ͬ��
ÿ�������������������������������ڿ��ƼĴ����еĿ����֣�����֮�乤����ȫ������
ÿ��������ͨ���������ź��ⲿ��ϵ��
һ��Ϊʱ�������CLK��һ��Ϊ�ſ��ź������GATE����һ��Ϊ�����OUT��
ÿ���������ڲ���һ��8λ�Ŀ��ƼĴ�����
����һ��16λ�ļ�����ֵ�Ĵ���CR��һ������ִ�в���CE��һ�����������OL��
ִ�в���ʵ������һ��16λ�ļ�����������
������ʼֵ���ǳ�ֵ�Ĵ�����ֵ������ʼֵ�Ĵ�����ֵ��ͨ���������õġ�
�����������ֵ��ͨ���������õġ�
���������OL�����������ִ�в���CE�����ݣ��Ӷ�ʹCPU���ԶԴ˽��ж�������
˳����һ�£�CR��CE��OL����16λ�Ĵ���������Ҳ������8λ�Ĵ������á�
*/


/*
 *	linux/kernel/softirq.c
 *
 *	Copyright (C) 1992 Linus Torvalds
 *
 *	Distribute under GPLv2.
 *
 *	Rewritten. Old one was good in 2.2, but in 2.3 it was immoral. --ANK (990903)
 *
 *	Remote softirq infrastructure is by Jens Axboe.
 */

#include <linux/export.h>
#include <linux/kernel_stat.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <linux/ftrace.h>
#include <linux/smp.h>
#include <linux/tick.h>

#define CREATE_TRACE_POINTS
#include <trace/events/irq.h>

#include <asm/irq.h>
/*
   - No shared variables, all the data are CPU local.
   - If a softirq needs serialization, let it serialize itself
     by its own spinlocks.
   - Even if softirq is serialized, only local cpu is marked for
     execution. Hence, we get something sort of weak cpu binding.
     Though it is still not clear, will it result in better locality
     or will not.

   Examples:
   - NET RX softirq. It is multithreaded and does not require
     any global serialization.
   - NET TX softirq. It kicks software netdevice queues, hence
     it is logically serialized per device, but this serialization
     is invisible to common code.
   - Tasklets: serialized wrt itself.

	wrt: with regard to 关于
 */

#ifndef __ARCH_IRQ_STAT
irq_cpustat_t irq_stat[NR_CPUS] ____cacheline_aligned;
EXPORT_SYMBOL(irq_stat);
#endif

/*
由open_softirq()为该数组添加软中断处理函数
*/
static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp;

DEFINE_PER_CPU(struct task_struct *, ksoftirqd);

char *softirq_to_name[NR_SOFTIRQS] = {
	"HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "BLOCK_IOPOLL",
	"TASKLET", "SCHED", "HRTIMER", "RCU"
};

/*
 * we cannot loop indefinitely here to avoid userspace starvation,
 * but we also don't want to introduce a worst case 1/HZ latency
 * to the pending events, so lets the scheduler to balance
 * the softirq load for us.
 */
static void wakeup_softirqd(void)
{
	/* Interrupts are disabled: no need to stop preemption */
	struct task_struct *tsk = __this_cpu_read(ksoftirqd);

	if (tsk && tsk->state != TASK_RUNNING)
		wake_up_process(tsk);
}

/*
 * preempt_count and SOFTIRQ_OFFSET usage:
 * - preempt_count is changed by SOFTIRQ_OFFSET on entering or leaving
 *   softirq processing.
 * - preempt_count is changed by SOFTIRQ_DISABLE_OFFSET (= 2 * SOFTIRQ_OFFSET)
 *   on local_bh_disable or local_bh_enable.
 * This lets us distinguish between whether we are currently processing
 * softirq and whether we just have bh disabled.
 */

/*
 * This one is for softirq.c-internal use,
 * where hardirqs are disabled legitimately:
 */
#ifdef CONFIG_TRACE_IRQFLAGS
static void __local_bh_disable(unsigned long ip, unsigned int cnt)
{
	unsigned long flags;

	WARN_ON_ONCE(in_irq());

	raw_local_irq_save(flags);
	/*
	 * The preempt tracer hooks into add_preempt_count and will break
	 * lockdep because it calls back into lockdep after SOFTIRQ_OFFSET
	 * is set and before current->softirq_enabled is cleared.
	 * We must manually increment preempt_count here and manually
	 * call the trace_preempt_off later.
	 */
	preempt_count() += cnt;
	/*
	 * Were softirqs turned off above:
	 */
	if (softirq_count() == cnt)
		trace_softirqs_off(ip);
	raw_local_irq_restore(flags);

	if (preempt_count() == cnt)
		trace_preempt_off(CALLER_ADDR0, get_parent_ip(CALLER_ADDR1));
}
#else /* !CONFIG_TRACE_IRQFLAGS */
static inline void __local_bh_disable(unsigned long ip, unsigned int cnt)
{
	add_preempt_count(cnt);
	barrier();
}
#endif /* CONFIG_TRACE_IRQFLAGS */

void local_bh_disable(void)
{
	__local_bh_disable((unsigned long)__builtin_return_address(0),
				SOFTIRQ_DISABLE_OFFSET);
}

EXPORT_SYMBOL(local_bh_disable);

static void __local_bh_enable(unsigned int cnt)
{
	WARN_ON_ONCE(in_irq());
	WARN_ON_ONCE(!irqs_disabled());

	if (softirq_count() == cnt)
		trace_softirqs_on((unsigned long)__builtin_return_address(0));
	sub_preempt_count(cnt);
}

/*
 * Special-case - softirqs can safely be enabled in
 * cond_resched_softirq(), or by __do_softirq(),
 * without processing still-pending softirqs:
 */
void _local_bh_enable(void)
{
	__local_bh_enable(SOFTIRQ_DISABLE_OFFSET);
}

EXPORT_SYMBOL(_local_bh_enable);

static inline void _local_bh_enable_ip(unsigned long ip)
{
	WARN_ON_ONCE(in_irq() || irqs_disabled());
#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_disable();
#endif
	/*
	 * Are softirqs going to be turned on now:
	 */
	if (softirq_count() == SOFTIRQ_DISABLE_OFFSET)
		trace_softirqs_on(ip);
	/*
	 * Keep preemption disabled until we are done with
	 * softirq processing:
 	 */
	sub_preempt_count(SOFTIRQ_DISABLE_OFFSET - 1);

	/* 看是否有挂起的软中断 */
	if (unlikely(!in_interrupt() && local_softirq_pending()))
		do_softirq();

	dec_preempt_count();
#ifdef CONFIG_TRACE_IRQFLAGS
	local_irq_enable();
#endif
	preempt_check_resched();
}

void local_bh_enable(void)
{
	_local_bh_enable_ip((unsigned long)__builtin_return_address(0));
}
EXPORT_SYMBOL(local_bh_enable);

void local_bh_enable_ip(unsigned long ip)
{
	_local_bh_enable_ip(ip);
}
EXPORT_SYMBOL(local_bh_enable_ip);

/*
 * We restart softirq processing MAX_SOFTIRQ_RESTART times,
 * and we fall back to softirqd after that.
 *
 * This number has been established via experimentation.
 * The two things to balance is latency against fairness -
 * we want to handle softirqs as soon as possible, but they
 * should not be able to lock up the box.
 */
/* 最大软中断调用次数为10次 */
#define MAX_SOFTIRQ_RESTART 10

asmlinkage void __do_softirq(void)
{
	/* 软件中断处理结构，此结构中包括了ISR中注册的回调函数 */
	struct softirq_action *h;
	__u32 pending;
	int max_restart = MAX_SOFTIRQ_RESTART;
	int cpu;

	/* 得到当前所有pending的软中断 */
	pending = local_softirq_pending();
	account_system_vtime(current);

	/* 执行到这里要屏蔽其他软中断，这里也就证明了每个CPU上同时运行的软中断只能有一个 */
	__local_bh_disable((unsigned long)__builtin_return_address(0),
				SOFTIRQ_OFFSET);
	lockdep_softirq_enter();

	/* 针对SMP得到当前正在处理的CPU */
	cpu = smp_processor_id();
restart:
	/* Reset the pending bitmask before enabling irqs */
	/* 每次循环在允许硬件ISR抢占前，首先重置软中断的标志位 */
	set_softirq_pending(0);

	/* 到这里才开中断运行，注意：以前运行状态一直是关中断运行，
	   这时当前处理软中断才可能被硬件中断抢占。
	   也就是说在进入软中断时不是一开始就会被硬件中断抢占。
	   只有在这里以后的代码才可能被硬件中断抢占。
	*/
	local_irq_enable();

	/* 这里要注意，以下代码运行时可以被硬件中断抢占，
	   但这个硬件ISR执行完成后，它所注册的软中断无法马上运行，
	   别忘了，现在虽是开硬件中断执行，但前面的__local_bh_disable()函数屏蔽了软中断。
	   所以这种环境下只能被硬件中断抢占，但这个硬中断注册的软中断回调函数无法运行。
	   要问为什么，那是因为__local_bh_disable()函数设置了一个标志当作互斥量，
	   而这个标志正是上面的irq_exit()和do_softirq()函数中的in_interrupt()函数判断的条件之一，
	   也就是说 in_interrupt()函数不仅检测硬中断而且还判断了软中断。
	   所以在这个环境下触发硬中断时注册的软中断，根本无法重新进入到这个函数中来，
	   只能是做一个标志，等待下面的重复循环(最大MAX_SOFTIRQ_RESTART)
	   才可能处理到这个时候触发的硬件中断所注册的软中断。
	*/

	/* 得到软中断向量表 */
	h = softirq_vec;

	/* 循环处理所有softirq软中断注册函数 */
	do {
		/* 如果对应的软中断设置pending标志则表明需要进一步处理它所注册的函数 */
		if (pending & 1) {
			unsigned int vec_nr = h - softirq_vec;
			int prev_count = preempt_count();

			kstat_incr_softirqs_this_cpu(vec_nr);

			trace_softirq_entry(vec_nr);
			h->action(h);
			trace_softirq_exit(vec_nr);
			if (unlikely(prev_count != preempt_count())) {
				printk(KERN_ERR "huh, entered softirq %u %s %p"
				       "with preempt_count %08x,"
				       " exited with %08x?\n", vec_nr,
				       softirq_to_name[vec_nr], h->action,
				       prev_count, preempt_count());
				preempt_count() = prev_count;
			}

			rcu_bh_qs(cpu);
		}
		/* 继续找，直到把软中断向量表中所有pending的软中断处理完成 */
		h++;
		/* 从代码里可以看出按位操作，表明一次循环只处理32个软中断的回调函数 */
		pending >>= 1;
	/* pending是32位无符号整数
	   对应softirq_vec的32项，softirq_vec数组大小就是32 */
	} while (pending);

	/* 关中断执行以下代码。
	   注意：这里又关中断了，下面的代码执行过程中硬件中断无法抢占。
	*/
	local_irq_disable();

	/* 前面提到过，在刚才开硬件中断执行环境时只能被硬件中断抢占，
	   在这个时候是无法处理软中断的，因为刚才开中断执行过程中可能多次被硬件中断抢占，
	   每抢占一次就有可能注册一个软中断，所以要再重新取一次所有的软中断。
	   以便下面的代码进行处理后跳回到restart处重复执行。
	*/
	pending = local_softirq_pending();
	/* 如果在上面的开中断执行环境中触发了硬件中断，且每个都注册了一个软中断的话，
	   这个软中断会设置pending位，但在当前一直屏蔽软中断的环境下无法得到执行，
	   前面提到过，因为irq_exit()和do_softirq()根本无法进入到这个处理过程中来。
	   这个在上面详细的记录过了。那么在这里又有了一个执行的机会。
	   注意:虽然当前环境一直是处于屏蔽软中断执行的环境中，
	   但在这里又给出了一个执行刚才在开中断环境过程中触发硬件中断时所注册的软中断的机会，
	   其实只要理解了软中断机制就会知道，
	   无非是在一些特定环境下调用ISR注册到软中断向量表里的函数而已。

	   如果刚才触发的硬件中断注册了软中断，并且重复执行次数没有到10次的话，
	   那么则跳转到restart标志处重复以上所介绍的所有步骤:设置软中断标志位，重新开中断执行...
	   注意:这里是要两个条件都满足的情况下才可能重复以上步骤。 
	*/
	if (pending && --max_restart)
		goto restart;

	/* 如果以上步骤重复了10次后还有pending的软中断的话，
	   那么系统在一定时间内可能达到了一个峰值，为了平衡这点。
	   系统专门建立了一个ksoftirqd线程来处理，这样避免在一定时间内负荷太大。
	   这个ksoftirqd线程本身是一个大循环，在某些条件下为了不使负载过重，
	   它是可以被其他进程抢占的，
	   但注意，它是显式的调用了preempt_xxx()和schedule()才会被抢占和切换的。
	   这么做的原因是因为在它一旦调用local_softirq_pending()函数
	   检测到有pending的软中断需要处理的时候，则会显式的调用do_softirq()来处理软中断。
	   也就是说，下面代码唤醒的ksoftirqd线程有可能会回到这个函数当中来，
	   尤其是在系统需要响应很多软中断的情况下，它的调用入口是do_softirq()，
	   这也就是为什么在do_softirq()的入口处也会用in_interrupt()函数
	   来判断是否有软中断正在处理的原因了，目的还是为了防止重入。
	*/
	if (pending)
		/* 调用wake_up_process()来唤醒ksoftirqd */
		wakeup_softirqd();

	lockdep_softirq_exit();

	account_system_vtime(current);
	/* 到最后才开软中断执行环境，允许软中断执行。
	   注意:这里使用的不是local_bh_enable()，不会再次触发do_softirq()的调用。
	*/
	__local_bh_enable(SOFTIRQ_OFFSET);
}

#ifndef __ARCH_HAS_DO_SOFTIRQ

asmlinkage void do_softirq(void)
{
	__u32 pending;
	unsigned long flags;

	/* 这个函数判断，如果当前有硬件中断嵌套，或者有软中断正在执行时候，则马上返回。
	   在这个入口判断主要是为了与ksoftirqd互斥。防止重入
	*/
	if (in_interrupt())
		return;

	/* 将CPU的flag值先储存到flags变数里，然后将CPU的中断disable掉。
	   这里将CPU的中断disable是指将执行这段code的CPU，并不是指全部的CPU。 
	   也就是说它只会disable local CPU的中断。
	*/
	local_irq_save(flags);

	pending = local_softirq_pending();

	/* 判断是否有pending的软中断需要处理 */
	if (pending)
		__do_softirq();

	/* 将flags里的值再设回CPU的flag里，开中断 */
	local_irq_restore(flags);
}

#endif

/*
 * Enter an interrupt context.
 */
/*
进入硬中断上下文
preempt_count里硬中断位+1
*/
void irq_enter(void)
{
	int cpu = smp_processor_id();

	rcu_irq_enter();
	if (idle_cpu(cpu) && !in_interrupt()) {
		/*
		 * Prevent raise_softirq from needlessly waking up ksoftirqd
		 * here, as softirq will be serviced on return from interrupt.
		 */
		local_bh_disable();
		tick_check_idle(cpu);
		_local_bh_enable();
	}

	__irq_enter();
}

#ifdef __ARCH_IRQ_EXIT_IRQS_DISABLED
static inline void invoke_softirq(void)
{
	if (!force_irqthreads)
		__do_softirq();
	else {
		__local_bh_disable((unsigned long)__builtin_return_address(0),
				SOFTIRQ_OFFSET);
		wakeup_softirqd();
		__local_bh_enable(SOFTIRQ_OFFSET);
	}
}
#else
static inline void invoke_softirq(void)
{
	if (!force_irqthreads)
		do_softirq();
	else {
		__local_bh_disable((unsigned long)__builtin_return_address(0),
				SOFTIRQ_OFFSET);
		wakeup_softirqd();
		__local_bh_enable(SOFTIRQ_OFFSET);
	}
}
#endif

/*
 * Exit an interrupt context. Process softirqs if needed and possible:
 */
void irq_exit(void)
{
	account_system_vtime(current);
	trace_hardirq_exit();
	/* 恢复preempt_count的值 */
	sub_preempt_count(IRQ_EXIT_OFFSET);
	/* 判断当前是否有硬件中断嵌套，并且是否有软中断在pending状态
	   注意:这里只有两个条件同时满足时，才有可能调用do_softirq()进入软中断
	   也就是说确认当前所有硬件中断处理完成，且有硬件中断安装了软中断处理时理时才会进入
	*/
	if (!in_interrupt() && local_softirq_pending())
		invoke_softirq();

	rcu_irq_exit();
#ifdef CONFIG_NO_HZ
	/* Make sure that timer wheel updates are propagated */
	if (idle_cpu(smp_processor_id()) && !in_interrupt() && !need_resched())
		tick_nohz_stop_sched_tick(0);
#endif
	preempt_enable_no_resched();
}

/*
 * This function must run with irqs disabled!
 */
inline void raise_softirq_irqoff(unsigned int nr)
{
	__raise_softirq_irqoff(nr);

	/*
	 * If we're in an interrupt or softirq, we're done
	 * (this also catches softirq-disabled code). We will
	 * actually run the softirq once we return from
	 * the irq or softirq.
	 *
	 * Otherwise we wake up ksoftirqd to make sure we
	 * schedule the softirq soon.
	 */
	if (!in_interrupt())
		wakeup_softirqd();
}

void raise_softirq(unsigned int nr)
{
	unsigned long flags;

	local_irq_save(flags);
	raise_softirq_irqoff(nr);
	local_irq_restore(flags);
}

void open_softirq(int nr, void (*action)(struct softirq_action *))
{
	softirq_vec[nr].action = action;
}

/*
 * Tasklets
 */
struct tasklet_head
{
	struct tasklet_struct *head;
	struct tasklet_struct **tail;
};

static DEFINE_PER_CPU(struct tasklet_head, tasklet_vec);
static DEFINE_PER_CPU(struct tasklet_head, tasklet_hi_vec);

void __tasklet_schedule(struct tasklet_struct *t)
{
	unsigned long flags;

	local_irq_save(flags);
	t->next = NULL;
	*__this_cpu_read(tasklet_vec.tail) = t;
	__this_cpu_write(tasklet_vec.tail, &(t->next));
	raise_softirq_irqoff(TASKLET_SOFTIRQ);
	local_irq_restore(flags);
}

EXPORT_SYMBOL(__tasklet_schedule);

void __tasklet_hi_schedule(struct tasklet_struct *t)
{
	unsigned long flags;

	local_irq_save(flags);
	t->next = NULL;
	*__this_cpu_read(tasklet_hi_vec.tail) = t;
	__this_cpu_write(tasklet_hi_vec.tail,  &(t->next));
	raise_softirq_irqoff(HI_SOFTIRQ);
	local_irq_restore(flags);
}

EXPORT_SYMBOL(__tasklet_hi_schedule);

void __tasklet_hi_schedule_first(struct tasklet_struct *t)
{
	BUG_ON(!irqs_disabled());

	t->next = __this_cpu_read(tasklet_hi_vec.head);
	__this_cpu_write(tasklet_hi_vec.head, t);
	__raise_softirq_irqoff(HI_SOFTIRQ);
}

EXPORT_SYMBOL(__tasklet_hi_schedule_first);

static void tasklet_action(struct softirq_action *a)
{
	struct tasklet_struct *list;

	local_irq_disable();
	list = __this_cpu_read(tasklet_vec.head);
	__this_cpu_write(tasklet_vec.head, NULL);
	__this_cpu_write(tasklet_vec.tail, &__get_cpu_var(tasklet_vec).head);
	local_irq_enable();

	while (list) {
		struct tasklet_struct *t = list;

		list = list->next;

		if (tasklet_trylock(t)) {
			if (!atomic_read(&t->count)) {
				if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
					BUG();
				t->func(t->data);
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}

		local_irq_disable();
		t->next = NULL;
		*__this_cpu_read(tasklet_vec.tail) = t;
		__this_cpu_write(tasklet_vec.tail, &(t->next));
		__raise_softirq_irqoff(TASKLET_SOFTIRQ);
		local_irq_enable();
	}
}

static void tasklet_hi_action(struct softirq_action *a)
{
	struct tasklet_struct *list;

	local_irq_disable();
	list = __this_cpu_read(tasklet_hi_vec.head);
	__this_cpu_write(tasklet_hi_vec.head, NULL);
	__this_cpu_write(tasklet_hi_vec.tail, &__get_cpu_var(tasklet_hi_vec).head);
	local_irq_enable();

	while (list) {
		struct tasklet_struct *t = list;

		list = list->next;

		if (tasklet_trylock(t)) {
			if (!atomic_read(&t->count)) {
				if (!test_and_clear_bit(TASKLET_STATE_SCHED, &t->state))
					BUG();
				t->func(t->data);
				tasklet_unlock(t);
				continue;
			}
			tasklet_unlock(t);
		}

		local_irq_disable();
		t->next = NULL;
		*__this_cpu_read(tasklet_hi_vec.tail) = t;
		__this_cpu_write(tasklet_hi_vec.tail, &(t->next));
		__raise_softirq_irqoff(HI_SOFTIRQ);
		local_irq_enable();
	}
}


void tasklet_init(struct tasklet_struct *t,
		  void (*func)(unsigned long), unsigned long data)
{
	t->next = NULL;
	t->state = 0;
	atomic_set(&t->count, 0);
	t->func = func;
	t->data = data;
}

EXPORT_SYMBOL(tasklet_init);

void tasklet_kill(struct tasklet_struct *t)
{
	if (in_interrupt())
		printk("Attempt to kill tasklet from interrupt\n");

	while (test_and_set_bit(TASKLET_STATE_SCHED, &t->state)) {
		do {
			yield();
		} while (test_bit(TASKLET_STATE_SCHED, &t->state));
	}
	tasklet_unlock_wait(t);
	clear_bit(TASKLET_STATE_SCHED, &t->state);
}

EXPORT_SYMBOL(tasklet_kill);

/*
 * tasklet_hrtimer
 */

/*
 * The trampoline is called when the hrtimer expires. It schedules a tasklet
 * to run __tasklet_hrtimer_trampoline() which in turn will call the intended
 * hrtimer callback, but from softirq context.
 */
static enum hrtimer_restart __hrtimer_tasklet_trampoline(struct hrtimer *timer)
{
	struct tasklet_hrtimer *ttimer =
		container_of(timer, struct tasklet_hrtimer, timer);

	tasklet_hi_schedule(&ttimer->tasklet);
	return HRTIMER_NORESTART;
}

/*
 * Helper function which calls the hrtimer callback from
 * tasklet/softirq context
 */
static void __tasklet_hrtimer_trampoline(unsigned long data)
{
	struct tasklet_hrtimer *ttimer = (void *)data;
	enum hrtimer_restart restart;

	restart = ttimer->function(&ttimer->timer);
	if (restart != HRTIMER_NORESTART)
		hrtimer_restart(&ttimer->timer);
}

/**
 * tasklet_hrtimer_init - Init a tasklet/hrtimer combo for softirq callbacks
 * @ttimer:	 tasklet_hrtimer which is initialized
 * @function:	 hrtimer callback function which gets called from softirq context
 * @which_clock: clock id (CLOCK_MONOTONIC/CLOCK_REALTIME)
 * @mode:	 hrtimer mode (HRTIMER_MODE_ABS/HRTIMER_MODE_REL)
 */
void tasklet_hrtimer_init(struct tasklet_hrtimer *ttimer,
			  enum hrtimer_restart (*function)(struct hrtimer *),
			  clockid_t which_clock, enum hrtimer_mode mode)
{
	hrtimer_init(&ttimer->timer, which_clock, mode);
	ttimer->timer.function = __hrtimer_tasklet_trampoline;
	tasklet_init(&ttimer->tasklet, __tasklet_hrtimer_trampoline,
		     (unsigned long)ttimer);
	ttimer->function = function;
}
EXPORT_SYMBOL_GPL(tasklet_hrtimer_init);

/*
 * Remote softirq bits
 */

DEFINE_PER_CPU(struct list_head [NR_SOFTIRQS], softirq_work_list);
EXPORT_PER_CPU_SYMBOL(softirq_work_list);

static void __local_trigger(struct call_single_data *cp, int softirq)
{
	struct list_head *head = &__get_cpu_var(softirq_work_list[softirq]);

	list_add_tail(&cp->list, head);

	/* Trigger the softirq only if the list was previously empty.  */
	if (head->next == &cp->list)
		raise_softirq_irqoff(softirq);
}

#ifdef CONFIG_USE_GENERIC_SMP_HELPERS
static void remote_softirq_receive(void *data)
{
	struct call_single_data *cp = data;
	unsigned long flags;
	int softirq;

	softirq = cp->priv;

	local_irq_save(flags);
	__local_trigger(cp, softirq);
	local_irq_restore(flags);
}

static int __try_remote_softirq(struct call_single_data *cp, int cpu, int softirq)
{
	if (cpu_online(cpu)) {
		cp->func = remote_softirq_receive;
		cp->info = cp;
		cp->flags = 0;
		cp->priv = softirq;

		__smp_call_function_single(cpu, cp, 0);
		return 0;
	}
	return 1;
}
#else /* CONFIG_USE_GENERIC_SMP_HELPERS */
static int __try_remote_softirq(struct call_single_data *cp, int cpu, int softirq)
{
	return 1;
}
#endif

/**
 * __send_remote_softirq - try to schedule softirq work on a remote cpu
 * @cp: private SMP call function data area
 * @cpu: the remote cpu
 * @this_cpu: the currently executing cpu
 * @softirq: the softirq for the work
 *
 * Attempt to schedule softirq work on a remote cpu.  If this cannot be
 * done, the work is instead queued up on the local cpu.
 *
 * Interrupts must be disabled.
 */
void __send_remote_softirq(struct call_single_data *cp, int cpu, int this_cpu, int softirq)
{
	if (cpu == this_cpu || __try_remote_softirq(cp, cpu, softirq))
		__local_trigger(cp, softirq);
}
EXPORT_SYMBOL(__send_remote_softirq);

/**
 * send_remote_softirq - try to schedule softirq work on a remote cpu
 * @cp: private SMP call function data area
 * @cpu: the remote cpu
 * @softirq: the softirq for the work
 *
 * Like __send_remote_softirq except that disabling interrupts and
 * computing the current cpu is done for the caller.
 */
void send_remote_softirq(struct call_single_data *cp, int cpu, int softirq)
{
	unsigned long flags;
	int this_cpu;

	local_irq_save(flags);
	this_cpu = smp_processor_id();
	__send_remote_softirq(cp, cpu, this_cpu, softirq);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(send_remote_softirq);

static int __cpuinit remote_softirq_cpu_notify(struct notifier_block *self,
					       unsigned long action, void *hcpu)
{
	/*
	 * If a CPU goes away, splice its entries to the current CPU
	 * and trigger a run of the softirq
	 */
	if (action == CPU_DEAD || action == CPU_DEAD_FROZEN) {
		int cpu = (unsigned long) hcpu;
		int i;

		local_irq_disable();
		for (i = 0; i < NR_SOFTIRQS; i++) {
			struct list_head *head = &per_cpu(softirq_work_list[i], cpu);
			struct list_head *local_head;

			if (list_empty(head))
				continue;

			local_head = &__get_cpu_var(softirq_work_list[i]);
			list_splice_init(head, local_head);
			raise_softirq_irqoff(i);
		}
		local_irq_enable();
	}

	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata remote_softirq_cpu_notifier = {
	.notifier_call	= remote_softirq_cpu_notify,
};

void __init softirq_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		int i;

		per_cpu(tasklet_vec, cpu).tail =
			&per_cpu(tasklet_vec, cpu).head;
		per_cpu(tasklet_hi_vec, cpu).tail =
			&per_cpu(tasklet_hi_vec, cpu).head;
		for (i = 0; i < NR_SOFTIRQS; i++)
			INIT_LIST_HEAD(&per_cpu(softirq_work_list[i], cpu));
	}

	register_hotcpu_notifier(&remote_softirq_cpu_notifier);

	/* 注册小任务的软中断处理函数 */
	open_softirq(TASKLET_SOFTIRQ, tasklet_action);
	open_softirq(HI_SOFTIRQ, tasklet_hi_action);
}

/*
每cpu的软中断守护进程

@__bind_cpu	: cpu号
*/
static int run_ksoftirqd(void * __bind_cpu)
{
	/* 设置当前进程状态为可中断的状态，这种睡眠状态可响应信号处理等。 */
	set_current_state(TASK_INTERRUPTIBLE);

	/* 下面是一个大循环，循环判断当前进程是否会停止，
	   不会则继续判断当前是否有pending的软中断需要处理。
	*/
	while (!kthread_should_stop()) {
		/* 如果可以进行处理，那么在此处理期间内禁止当前进程被抢占。 */
		preempt_disable();
		/* 首先判断系统当前没有需要处理的pending状态的软中断 */
		if (!local_softirq_pending()) {
			/* 没有的话则主动放弃CPU前先要允许抢占，
			   因为一直是在不允许抢占状态下执行的代码。 */
			preempt_enable_no_resched();
			/* 显式调用此函数主动放弃CPU将当前进程放入睡眠队列，
			   并切换新的进程执行(调度器相关不记录在此) */
			schedule();
			/* 注意:如果当前显式调用schedule()函数主动切换的进程再次被调度执行的话，
			   那么将从调用这个函数的下一条语句开始执行。
			   也就是说，在这里当前进程再次被执行的话，
			   将会执行下面的preempt_disable()函数。

			   当进程再度被调度时，在以下处理期间内禁止当前进程被抢占。
			*/
			preempt_disable();
		}

		/* 设置当前进程为运行状态。
		   注意:已经设置了当前进程不可抢占在进入循环后，
		   以上两个分支不论走哪个都会执行到这里。
		   一是进入循环时就有pending的软中断需要执行时。
		   二是进入循环时没有pending的软中断，当前进程再次被调度获得CPU时继续执行时。
		*/
		__set_current_state(TASK_RUNNING);

		/* 循环判断是否有pending的软中断，
		   如果有则调用do_softirq()来做具体处理。
		   注意:这里又是一个do_softirq()的入口点，
		   那么在__do_softirq()当中循环处理10次软中断的回调函数后，
		   如果还有pending的话，会又调用到这里。
		   那么在这里则又会有可能去调用__do_softirq()来处理软中断回调函数。
		   在前面介绍__do_softirq()时已经提到过，
		   处理10次还处理不完的话说明系统正处于繁忙状态。
		   根据以上分析，我们可以试想如果在系统非常繁忙时，
		   这个进程将会与do_softirq()相互交替执行，
		   这时此进程占用CPU应该会很高，虽然下面的cond_resched()函数做了一些处理，
		   它在处理完一轮软中断后当前处理进程可能会因被调度而减少CPU负荷，
		   但是在非常繁忙时这个进程仍然有可能大量占用CPU。
		*/
		while (local_softirq_pending()) {
			/* Preempt disable stops cpu going offline.
			   If already offline, we'll be on wrong CPU:
			   don't process */
			/* 如果当前被关联的CPU无法继续处理则跳转到wait_to_die标记出，
			   等待结束并退出。
			*/
			if (cpu_is_offline((long)__bind_cpu))
				goto wait_to_die;
			local_irq_disable();
			/* 执行__do_softirq()来处理具体的软中断回调函数 */
			if (local_softirq_pending())
				__do_softirq();
			local_irq_enable();
			/* 允许当前进程被抢占 */
			preempt_enable_no_resched();
			/* 这个函数有可能间接的调用schedule()来切换当前进程，
			   而且上面已经允许当前进程可被抢占。
			   也就是说在处理完一轮软中断回调函数时，
			   有可能会切换到其他进程。
			   这样做的目的一是为了在某些负载超标的情况下
			   不至于让这个进程长时间大量的占用 CPU，
			   二是让在有很多软中断需要处理时不至于让其他进程得不到响应。
			*/
			cond_resched();
			/* 禁止当前进程被抢占 */
			preempt_disable();
			rcu_note_context_switch((long)__bind_cpu);
		/* 处理完所有软中断了吗?没有的话继续循环以上步骤 */
		}
		/* 待一切都处理完成后，允许当前进程被抢占，
		   并设置当前进程状态为可中断状态，继续循环以上所有过程。
		*/
		preempt_enable();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	/* 如果将会停止则设置当前进程为运行状态后直接返回。
	   调度器会根据优先级来使当前进程运行。
	*/
	__set_current_state(TASK_RUNNING);
	return 0;

wait_to_die:
	preempt_enable();
	/* Wait for kthread_stop */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	__set_current_state(TASK_RUNNING);
	return 0;
}

#ifdef CONFIG_HOTPLUG_CPU
/*
 * tasklet_kill_immediate is called to remove a tasklet which can already be
 * scheduled for execution on @cpu.
 *
 * Unlike tasklet_kill, this function removes the tasklet
 * _immediately_, even if the tasklet is in TASKLET_STATE_SCHED state.
 *
 * When this function is called, @cpu must be in the CPU_DEAD state.
 */
void tasklet_kill_immediate(struct tasklet_struct *t, unsigned int cpu)
{
	struct tasklet_struct **i;

	BUG_ON(cpu_online(cpu));
	BUG_ON(test_bit(TASKLET_STATE_RUN, &t->state));

	if (!test_bit(TASKLET_STATE_SCHED, &t->state))
		return;

	/* CPU is dead, so no lock needed. */
	for (i = &per_cpu(tasklet_vec, cpu).head; *i; i = &(*i)->next) {
		if (*i == t) {
			*i = t->next;
			/* If this was the tail element, move the tail ptr */
			if (*i == NULL)
				per_cpu(tasklet_vec, cpu).tail = i;
			return;
		}
	}
	BUG();
}

static void takeover_tasklets(unsigned int cpu)
{
	/* CPU is dead, so no lock needed. */
	local_irq_disable();

	/* Find end, append list for that CPU. */
	if (&per_cpu(tasklet_vec, cpu).head != per_cpu(tasklet_vec, cpu).tail) {
		*__this_cpu_read(tasklet_vec.tail) = per_cpu(tasklet_vec, cpu).head;
		this_cpu_write(tasklet_vec.tail, per_cpu(tasklet_vec, cpu).tail);
		per_cpu(tasklet_vec, cpu).head = NULL;
		per_cpu(tasklet_vec, cpu).tail = &per_cpu(tasklet_vec, cpu).head;
	}
	raise_softirq_irqoff(TASKLET_SOFTIRQ);

	if (&per_cpu(tasklet_hi_vec, cpu).head != per_cpu(tasklet_hi_vec, cpu).tail) {
		*__this_cpu_read(tasklet_hi_vec.tail) = per_cpu(tasklet_hi_vec, cpu).head;
		__this_cpu_write(tasklet_hi_vec.tail, per_cpu(tasklet_hi_vec, cpu).tail);
		per_cpu(tasklet_hi_vec, cpu).head = NULL;
		per_cpu(tasklet_hi_vec, cpu).tail = &per_cpu(tasklet_hi_vec, cpu).head;
	}
	raise_softirq_irqoff(HI_SOFTIRQ);

	local_irq_enable();
}
#endif /* CONFIG_HOTPLUG_CPU */

static int __cpuinit cpu_callback(struct notifier_block *nfb,
				  unsigned long action,
				  void *hcpu)
{
	int hotcpu = (unsigned long)hcpu;
	struct task_struct *p;

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		p = kthread_create_on_node(run_ksoftirqd,
					   hcpu,
					   cpu_to_node(hotcpu),
					   "ksoftirqd/%d", hotcpu);
		if (IS_ERR(p)) {
			printk("ksoftirqd for %i failed\n", hotcpu);
			return notifier_from_errno(PTR_ERR(p));
		}
		kthread_bind(p, hotcpu);
  		per_cpu(ksoftirqd, hotcpu) = p;
 		break;
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		wake_up_process(per_cpu(ksoftirqd, hotcpu));
		break;
#ifdef CONFIG_HOTPLUG_CPU
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
		if (!per_cpu(ksoftirqd, hotcpu))
			break;
		/* Unbind so it can run.  Fall thru. */
		kthread_bind(per_cpu(ksoftirqd, hotcpu),
			     cpumask_any(cpu_online_mask));
	case CPU_DEAD:
	case CPU_DEAD_FROZEN: {
		static const struct sched_param param = {
			.sched_priority = MAX_RT_PRIO-1
		};

		p = per_cpu(ksoftirqd, hotcpu);
		per_cpu(ksoftirqd, hotcpu) = NULL;
		sched_setscheduler_nocheck(p, SCHED_FIFO, &param);
		kthread_stop(p);
		takeover_tasklets(hotcpu);
		break;
	}
#endif /* CONFIG_HOTPLUG_CPU */
 	}
	return NOTIFY_OK;
}

static struct notifier_block __cpuinitdata cpu_nfb = {
	.notifier_call = cpu_callback
};

static __init int spawn_ksoftirqd(void)
{
	void *cpu = (void *)(long)smp_processor_id();
	int err = cpu_callback(&cpu_nfb, CPU_UP_PREPARE, cpu);

	BUG_ON(err != NOTIFY_OK);
	cpu_callback(&cpu_nfb, CPU_ONLINE, cpu);
	register_cpu_notifier(&cpu_nfb);
	return 0;
}
early_initcall(spawn_ksoftirqd);

/*
 * [ These __weak aliases are kept in a separate compilation unit, so that
 *   GCC does not inline them incorrectly. ]
 */

int __init __weak early_irq_init(void)
{
	return 0;
}

#ifdef CONFIG_GENERIC_HARDIRQS
int __init __weak arch_probe_nr_irqs(void)
{
	return NR_IRQS_LEGACY;
}

int __init __weak arch_early_irq_init(void)
{
	return 0;
}
#endif

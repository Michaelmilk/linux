#ifndef _ASM_X86_I8253_H
#define _ASM_X86_I8253_H

/* i8253A PIT registers */
/*
通过端口0x43写入一个8bit的控制字
*/
#define PIT_MODE		0x43
/*
pit的0通道
否则更新系统时钟
当一个滴答过去，计数器减为0时，通过IRQ0产生一次时钟中断
*/
#define PIT_CH0			0x40
#define PIT_CH2			0x42

#define PIT_LATCH	LATCH

extern raw_spinlock_t i8253_lock;

extern struct clock_event_device *global_clock_event;

extern void setup_pit_timer(void);

#define inb_pit		inb_p
#define outb_pit	outb_p

#endif /* _ASM_X86_I8253_H */

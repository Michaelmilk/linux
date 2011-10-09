#ifndef _ASM_X86_I8253_H
#define _ASM_X86_I8253_H

/* i8253A PIT registers */
/*
ͨ���˿�0x43д��һ��8bit�Ŀ�����
*/
#define PIT_MODE		0x43
/*
pit��0ͨ��
�������ϵͳʱ��
��һ���δ��ȥ����������Ϊ0ʱ��ͨ��IRQ0����һ��ʱ���ж�
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

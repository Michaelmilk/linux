/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 *   This file is part of the Linux kernel, and is made available under
 *   the terms of the GNU General Public License version 2.
 *
 * ----------------------------------------------------------------------- */

/*
 * Prepare the machine for transition to protected mode.
 */

#include "boot.h"
#include <asm/segment.h>

/*
 * Invoke the realmode switch hook if present; otherwise
 * disable all interrupts.
 */
/*
�ο�Documentation/x86/boot.txt
���bootloaderָ����ʵģʽhook�Ļ������ȵ���
û�еĻ�����жϣ�����NMI
*/
static void realmode_switch_hook(void)
{
	/* ���뱣��ģʽǰ������hdr�е�realmode_swtchָ���hook����
	   boot loader��������realmode_swtch��ʵģʽ��ִ��ĳЩ�����������
	*/
	if (boot_params.hdr.realmode_swtch) {
		/* ������16λ��ַ
		   %0ȡ����ֵrealmode_swtch
		   *%0ǰ��"*"�ű�ʾȡ��Ϊ���Ե�ַ */
		asm volatile("lcallw *%0"
			     : : "m" (boot_params.hdr.realmode_swtch)
			     : "eax", "ebx", "ecx", "edx");
	} else {
		/* ʹ��cliָ��
		   ��IFλ��0(���ж�) */
		asm volatile("cli");
		/* NMI: NonMaskable Interrupt ���������ж�����
		   ����״̬�Ĵ����� IF λ��״̬���,CPU�յ���Ч��NMI���������Ӧ;
		   NMI����������Ч;�ж����ͺŹ̶�Ϊ2;���ڱ���Ӧʱ���ж���Ӧ����.
		   ���������ж�ͨ�����ڹ��ϴ���
		   (��:Э�������������,�洢��У�����,I/Oͨ��У������). 

		   ��0x70�˿ڵ�bit7��1����Disable NMI */
		outb(0x80, 0x70); /* Disable NMI */
		io_delay();
	}
}

/*
 * Disable all interrupts at the legacy PIC.
 */
static void mask_all_interrupts(void)
{
	outb(0xff, 0xa1);	/* Mask all interrupts on the secondary PIC */
	io_delay();
	outb(0xfb, 0x21);	/* Mask all but cascade on the primary PIC */
	io_delay();
}

/*
 * Reset IGNNE# if asserted in the FPU.
 */
static void reset_coprocessor(void)
{
	outb(0, 0xf0);
	io_delay();
	outb(0, 0xf1);
	io_delay();
}

/*
 * Set up the GDT
 */

struct gdt_ptr {
	u16 len;
	u32 ptr;
} __attribute__((packed));

static void setup_gdt(void)
{
	/* There are machines which are known to not boot with the GDT
	   being 8-byte unaligned.  Intel recommends 16 byte alignment. */
	static const u64 boot_gdt[] __attribute__((aligned(16))) = {
        /* CS��DS��flags = 0xc0(11000000)
		   �������ȱ�־Gr=1���δ�С��4KB�ơ�B=1��ָ��ƫ�����ĵ�ַ��32λ����

		   0x9b(10011011)
		   0x93(10010011)
		   P(��47bit)������Ϊ1
		   DPLΪ0������2������Ҫ�ں�̬�ſɷ��ʡ�

		   limitΪ0xfffff��G�Ѿ���Ϊ1���δ�С��4KB�ƣ���������Ϊ4GB��

		   type��4bit��˵���εľ�������
		   type0ָʾ�������Ƿ񱻷��ʣ���A��ǡ�
				A=0����ʾ������δ�����ʡ�
				A=1����ʾ�������ѱ����ʡ�
		   type1
		   type2
		   type3ָʾ�������ݶλ��Ǵ���Σ���E��ǡ�
		        E=1��ʾ��ִ�жΣ�Ҳ���Ǵ���Σ���Ӧ��������Ҳ���Ǵ������������
		        E=0��ʾ����ִ�жΣ������ݶΣ���Ӧ��������Ҳ�������ݶ���������

		   ��type3=1ʱ��������Ρ�
						type1ָʾ�ô�����Ƿ�ɶ�����R��ǡ�
		                     R=0����ʾ��Ӧ�Ĵ���β��ɶ���ֻ��ִ�С�
		                     R=1����ʾ��Ӧ�Ĵ���οɶ���ִ�С�
		                type2ָʾ������Ƿ���һ�´���Σ���C��ʾ��
				             C=0����ʾ����β���һ�´���Ρ�
				             C=1����ʾ��һ�´���Ρ�

		   ��type3=0ʱ�������ݶΡ�
						type1ָʾ�����ݶ��Ƿ��д����W��ǡ�
		                     W=0����ʾ��Ӧ�����ݶβ���д��ֻ����
							 W=1����ʾ��Ӧ�����ݶο�д��
						type2ָʾ���ݶε���չ������ED��ǡ�
							 ED=0����ʾ��߶���չ��
							 ED=1����ʾ��Ͷ���չ��

 * 31          24         19   16                 7           0
 * ------------------------------------------------------------
 * |             | |B| |A|       | |   |1|0|E|W|A|            |
 * | BASE 31..24 |G|/|0|V| LIMIT |P|DPL|  TYPE   | BASE 23:16 |
 * |             | |D| |L| 19..16| |   |1|1|C|R|A|            |
 * ------------------------------------------------------------
 * |                             |                            |
 * |        BASE 15..0           |       LIMIT 15..0          |
 * |                             |                            |
 * ------------------------------------------------------------
 from grub

        */

		/* CS: code, read/execute, 4 GB, base 0 */
		[GDT_ENTRY_BOOT_CS] = GDT_ENTRY(0xc09b, 0, 0xfffff),
		/* DS: data, read/write, 4 GB, base 0 */
		[GDT_ENTRY_BOOT_DS] = GDT_ENTRY(0xc093, 0, 0xfffff),
		/* TSS: 32-bit tss, 104 bytes, base 4096 */
		/* We only have a TSS here to keep Intel VT happy;
		   we don't actually use it for anything. */
		[GDT_ENTRY_BOOT_TSS] = GDT_ENTRY(0x0089, 4096, 103),
	};
	/* Xen HVM incorrectly stores a pointer to the gdt_ptr, instead
	   of the gdt_ptr contents.  Thus, make it static so it will
	   stay in memory, at least long enough that we switch to the
	   proper kernel GDT. */
	static struct gdt_ptr gdt;

	gdt.len = sizeof(boot_gdt)-1;
	/* Ŀǰ�����ڱ���ģʽ
	   ʹ�� ��:ƫ�� �ķ�ʽȡ�����Ե�ַ���������ַ */
	gdt.ptr = (u32)&boot_gdt + (ds() << 4);

	/* lgdtl: load gloabl descriptor table(GDT) register
	   ����������ڼ�ʹ�õ�boot_gdt���ؽ�gdtr�Ĵ��� */
	asm volatile("lgdtl %0" : : "m" (gdt));
}

/*
 * Set up the IDT
 */
static void setup_idt(void)
{
	static const struct gdt_ptr null_idt = {0, 0};
	/* lidtl: load interrupt descriptor table(IDT) register */
	asm volatile("lidtl %0" : : "m" (null_idt));
}

/*
 * Actual invocation sequence
 */
void go_to_protected_mode(void)
{
	/* Hook before leaving real mode, also disables interrupts */
	realmode_switch_hook();

	/* Enable the A20 gate */
	if (enable_a20()) {
		puts("A20 gate not responding, unable to boot...\n");
		die();
	}

	/* Reset coprocessor (IGNNE#) */
	reset_coprocessor();

	/* Mask all interrupts in the PIC */
	mask_all_interrupts();

	/* Actual transition to protected mode... */
	/* ׼�����뱣��ģʽ
	   �����ж���������Ϊ��
	   ����realmode_switch_hook()�й��ж��ˣ���������Ҳ�Ͳ���ҪIDT */
	setup_idt();
	/* ����ȫ�ֶ��������� */
	setup_gdt();
	/* ��һ������boot_params.hdr.code32_start��(arch/i386/boot/header.s)�и�ֵ
	   ����ת��0x1000��0x100000������ִ�С�
	   �ڶ������������� boot_params�����Ե�ַ��
	   ע�⣬��������ʵ��ַģʽ�����Ե�ַΪ�ε�ַ��16����ƫ�ơ�

	   ds�Ĵ������ڵ�ַΪ0x9000������4λΪ0x90000
	   &boot_paramsȡ���ĵ�ַΪ����boot_params��Ŀ���ļ��ڵ�ƫ��
	   setup�Ǽ��ص������ַ0x7c00����
	   ����(ds() << 4)��õ�����boot_params��ʱ�������ڴ��е������ַ

	   protected_mode_jump()������arch/x86/boot/pmjump.S�� */
	protected_mode_jump(boot_params.hdr.code32_start,
			    (u32)&boot_params + (ds() << 4));
}

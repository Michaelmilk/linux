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
参考Documentation/x86/boot.txt
如果bootloader指定了实模式hook的话，则先调用
没有的话则关中断，屏蔽NMI
*/
static void realmode_switch_hook(void)
{
	/* 进入保护模式前，调用hdr中的realmode_swtch指向的hook函数
	   boot loader可以利用realmode_swtch在实模式下执行某些代码的最后机会
	*/
	if (boot_params.hdr.realmode_swtch) {
		/* 长调用16位地址
		   %0取输入值realmode_swtch
		   *%0前的"*"号表示取的为绝对地址 */
		asm volatile("lcallw *%0"
			     : : "m" (boot_params.hdr.realmode_swtch)
			     : "eax", "ebx", "ecx", "edx");
	} else {
		/* 使用cli指令
		   将IF位置0(关中断) */
		asm volatile("cli");
		/* NMI: NonMaskable Interrupt 不可屏蔽中断请求
		   无论状态寄存器中 IF 位的状态如何,CPU收到有效的NMI必须进行响应;
		   NMI是上升沿有效;中断类型号固定为2;它在被响应时无中断响应周期.
		   不可屏蔽中断通常用于故障处理
		   (如:协处理器运算出错,存储器校验出错,I/O通道校验出错等). 

		   将0x70端口的bit7置1，即Disable NMI */
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
        /* CS和DS的flags = 0xc0(11000000)
		   所以粒度标志Gr=1，段大小以4KB计。B=1，指段偏移量的地址是32位长。

		   0x9b(10011011)
		   0x93(10010011)
		   P(第47bit)总是置为1
		   DPL为0，即这2个段需要内核态才可访问。

		   limit为0xfffff，G已经置为1，段大小以4KB计，即段上限为4GB。

		   type共4bit，说明段的具体属性
		   type0指示描述符是否被访问，用A标记。
				A=0，表示描述符未被访问。
				A=1，表示描述符已被访问。
		   type1
		   type2
		   type3指示段是数据段还是代码段，用E标记。
		        E=1表示可执行段，也就是代码段，对应的描述符也就是代码段描述符。
		        E=0表示不可执行段，是数据段，对应的描述符也就是数据段描述符。

		   当type3=1时，即代码段。
						type1指示该代码段是否可读，用R标记。
		                     R=0，表示对应的代码段不可读，只能执行。
		                     R=1，表示对应的代码段可读可执行。
		                type2指示代码段是否是一致代码段，用C表示。
				             C=0，表示代码段不是一致代码段。
				             C=1，表示是一致代码段。

		   当type3=0时，即数据段。
						type1指示该数据段是否可写，用W标记。
		                     W=0，表示对应的数据段不可写，只读。
							 W=1，表示对应的数据段可写。
						type2指示数据段的扩展方向，用ED标记。
							 ED=0，表示向高端扩展。
							 ED=1，表示向低端扩展。

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
	/* 目前还处于保护模式
	   使用 段:偏移 的方式取得线性地址，即物理地址 */
	gdt.ptr = (u32)&boot_gdt + (ds() << 4);

	/* lgdtl: load gloabl descriptor table(GDT) register
	   将这个引导期间使用的boot_gdt加载进gdtr寄存器 */
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
	/* 准备进入保护模式
	   设置中断描述符表为空
	   上面realmode_switch_hook()中关中断了，所以这里也就不需要IDT */
	setup_idt();
	/* 设置全局段描述符表 */
	setup_gdt();
	/* 第一个参数boot_params.hdr.code32_start在(arch/i386/boot/header.s)中赋值
	   即跳转到0x1000或0x100000处继续执行。
	   第二个参数，就是 boot_params的线性地址，
	   注意，现在仍是实地址模式，线性地址为段地址乘16加上偏移。

	   ds寄存器段内地址为0x9000，左移4位为0x90000
	   &boot_params取到的地址为参数boot_params在目标文件内的偏移
	   setup是加载到物理地址0x7c00处的
	   加上(ds() << 4)后得到的是boot_params此时在物理内存中的物理地址

	   protected_mode_jump()定义在arch/x86/boot/pmjump.S内 */
	protected_mode_jump(boot_params.hdr.code32_start,
			    (u32)&boot_params + (ds() << 4));
}

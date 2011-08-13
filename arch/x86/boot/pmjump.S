/* ----------------------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *
 *   This file is part of the Linux kernel, and is made available under
 *   the terms of the GNU General Public License version 2.
 *
 * ----------------------------------------------------------------------- */

/*
 * The actual transition into protected mode
 */

#include <asm/boot.h>
#include <asm/processor-flags.h>
#include <asm/segment.h>
#include <linux/linkage.h>

	/* 使用code16告诉编译器，下面的代码要编译成16位代码
	   即编译成16位实模式代码 */

	.text
	.code16

/*
 * void protected_mode_jump(u32 entrypoint, u32 bootparams);
 */
GLOBAL(protected_mode_jump)
	/* edx寄存器内的值为指针指向main.c中定义的全局变量boot_params
	   即其物理地址，现在仍处于实模式
	   将其值保存在esi寄存器中 */
	movl	%edx, %esi		# Pointer to boot_params table

	/* ebx寄存器清0
	   cs代码段寄存器值放入bx寄存器，ebx的低16bit
	   段寄存器的值左移4位
	   加上下面2标号处的偏移值，得到其物理地址，保存到2标号处
	   即计算出in_pm32的物理地址
	   下面跳转的时候已经进入保护模式，基址为0，所以这里算出的值等于物理地址 */
	xorl	%ebx, %ebx
	movw	%cs, %bx
	shll	$4, %ebx
	addl	%ebx, 2f
	jmp	1f			# Short jump to serialize on 386/486
1:

	/* GDT表已经在go_to_protected_mode()中的setup_gdt()处设置

	   设置代码段选择子 */
	movw	$__BOOT_DS, %cx
	/* 设置任务栈段选择子 */
	movw	$__BOOT_TSS, %di

	/* 将cr0控制寄存器中的值取出放在edx寄存器内
	   edx寄存器为32bit，dl寄存器为其第8bit
	   把PE位标志或上后再写回cr0寄存器，即让cpu进入保护模式
	   PG位仍为0，此时还没有启用分页*/
	movl	%cr0, %edx
	orb	$X86_CR0_PE, %dl	# Protected mode
	movl	%edx, %cr0

	# Transition to 32-bit mode
	/* 跳转到in_pm32执行32位模式代码 */
	.byte	0x66, 0xea		# ljmpl opcode
	/* 偏移值，由上面计算而来 */
2:	.long	in_pm32			# offset
	/* 代码段选择子0x10，基址为0 */
	.word	__BOOT_CS		# segment
ENDPROC(protected_mode_jump)

	/* 此处后面的代码已经进入了32位保护模式
	   in_pm32即in protected mode 32

	   code32告诉编译器，下面的代码编译成32位代码
	   即编译成32位保护模式代码 */

	.code32
	.section ".text32","ax"
GLOBAL(in_pm32)
	# Set up data segments for flat 32-bit mode
	/* 设置各个段选择子 */
	movl	%ecx, %ds
	movl	%ecx, %es
	movl	%ecx, %fs
	movl	%ecx, %gs
	movl	%ecx, %ss
	# The 32-bit code sets up its own stack, but this way we do have
	# a valid stack if some debugging hack wants to use it.
	addl	%ebx, %esp

	# Set up TR to make Intel VT happy
	/* ltr: load task register */
	ltr	%di

	# Clear registers to allow for future extensions to the
	# 32-bit boot protocol
	xorl	%ecx, %ecx
	xorl	%edx, %edx
	xorl	%ebx, %ebx
	xorl	%ebp, %ebp
	xorl	%edi, %edi

	# Set up LDTR to make Intel VT happy
	/* lldt: load local descriptor table(LDT) register */
	lldt	%cx

	/* eax寄存器中的值即pm.c中调用protected_mode_jump()时第一个参数传来的值
	   即boot_params.hdr.code32_start
	   该值由main.c中的函数main()调用copy_boot_params()从header.S中的hdr处复制而来
	   查看header.S中code32_start处的值即0x100000
	   此物理地址处的代码即vmlinux.bin，由grub从bzImage中复制而来
	   使用objdump -d查看arch/x86/boot/compressed/vmlinux，
	   其指令即arch/x86/boot/compressed/head_32.S中startup_32处开始 */
	jmpl	*%eax			# Jump to the 32-bit entrypoint
ENDPROC(in_pm32)

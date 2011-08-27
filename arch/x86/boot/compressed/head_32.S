/*
 *  linux/boot/head.S
 *
 *  Copyright (C) 1991, 1992, 1993  Linus Torvalds
 */

/*
 *  head.S contains the 32-bit startup code.
 *
 * NOTE!!! Startup happens at absolute address 0x00001000, which is also where
 * the page directory will exist. The startup code will be overwritten by
 * the page directory. [According to comments etc elsewhere on a compressed
 * kernel it will end up at 0x1000 + 1Mb I hope so as I assume this. - AC]
 *
 * Page 0 is deliberately kept safe, since System Management Mode code in
 * laptops may need to access the BIOS data stored there.  This is also
 * useful for future device drivers that either access the BIOS via VM86
 * mode.
 */

/*
 * High loaded stuff by Hans Lermen & Werner Almesberger, Feb. 1996
 */

/*
在连接脚本arch/x86/boot/compressed/vmlinux.lds中
把这里的符号startup_32作为arch/x86/boot/compressed/vmlinux的起始地址
*/

	.text

#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/page_types.h>
#include <asm/boot.h>
#include <asm/asm-offsets.h>

/*
这里的代码即bzImage的第二部分vmlinux.bin起始代码
由grub复制在物理地址0x100000处
*/

/*
__HEAD在include/linux/init.h内定义为
#define __HEAD		.section	".head.text","ax"
所以下面这段代码是连接在arch/x86/boot/compressed/vmlinux.lds.S中.head.text节的
*/

	__HEAD
ENTRY(startup_32)
	/* 对连接好的arch/x86/boot/compressed/vmlinux使用objdump -d得到的信息
	   第一条命令就是这里的cld
	   DF标志置0，指示地址方向为增加 */
	cld
	/*
	 * Test KEEP_SEGMENTS flag to see if the bootloader is asking
	 * us to not reload segments
	 */
	/* 检查bit6的KEEP_SEGMENTS标志是否置位
	   参考Documentation/x86/boot.txt */
	testb	$(1<<6), BP_loadflags(%esi)
	/* 如果置位的话，则跳过下面重新加载段选择子的操作 */
	jnz	1f

	/* 清除IF标志，关闭中断 */
	cli
	/* 引导数据段选择子放入eax寄存器
	   这里已经进入保护模式了
	   __BOOT_DS定义在arch/x86/include/asm/segment.h中
	   参考Documentation/x86/boot.txt */
	movl	$__BOOT_DS, %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs
	movl	%eax, %ss
1:

/*
 * Calculate the delta between where we were compiled to run
 * at and where we were actually loaded at.  This can only be done
 * with a short local call on x86.  Nothing  else will tell us what
 * address we are running at.  The reserved chunk of the real-mode
 * data at 0x1e4 (defined as a scratch field) are used as the stack
 * for this calculation. Only 4 bytes are needed.
 */
	/* scratch为结构struct boot_params中的字段，在结构中的偏移为0x1e4
	   esi寄存器在protected_mode_jump跳转时，保存的是boot_params的线性地址
	   参考pmjump.S中的protected_mode_jump()
	   0x1e4 + 4 = 0x1e8
	   栈顶指针esp指向scratch字段末尾处

	   leal: load effective address
	   */
	leal	(BP_scratch+4)(%esi), %esp
	/* call调用，将当前的%eip入栈
	   此时%eip指向标号1:处指令的线性地址
	   即将值存入了boot_params的scratch字段 */
	call	1f
	/* 出栈，即scratch字段的值保存到了ebp寄存器
	   即ebp中值为标号1:的实际物理地址 */
1:	popl	%ebp
	/* 1b指的是backward，即前1句标号1的地址偏移值
	   %ebp减去标号1:的偏移，即得到startup_32的实际物理地址了 */
	subl	$1b, %ebp

/*
 * %ebp contains the address we are loaded at by the boot loader and %ebx
 * contains the address where we should move the kernel image temporarily
 * for safe in-place decompression.
 */

/*
此时%ebp内的值为boot loader加载内核的物理地址
下面会计算一个临时地址存入%ebx内
该临时地址保存未解压的代码
*/

/*
relocate : 迁移
根据内核不同的配置做不同的处理
计算解压后内核代码的物理地址
*/
#ifdef CONFIG_RELOCATABLE
	/* 当前startup_32的物理地址 */
	movl	%ebp, %ebx
	/* BP_kernel_alignment定义在arch/x86/kernel/asm-offsets.c中
	   esi寄存器中的地址依然为boot_params的线性地址
	   加上BP_kernel_alignment后
	   即struct setup_header的kernel_alignment字段的值，存入eax寄存器 */
	movl	BP_kernel_alignment(%esi), %eax
	/* 减1，相加，取反，按位与
	   即按照对齐的值进行对齐 */
	decl	%eax
	addl    %eax, %ebx
	/* notl: bitwise logical NOT */
	notl	%eax
	andl    %eax, %ebx
#else
	movl	$LOAD_PHYSICAL_ADDR, %ebx
#endif

	/* Target address to relocate to for decompression */
	/* z_extract_offset为压缩文件填补对齐后的大小
	   参考arch/x86/boot/compressed/mkpiggy.c
	   %ebx增加解压需要的偏移量，指向一个用于移动压缩代码的临时位置 */
	addl	$z_extract_offset, %ebx

	/* Set up the stack */
	leal	boot_stack_end(%ebx), %esp

	/* Zero EFLAGS */
	pushl	$0
	/* popfl: pop %eflags from stack */
	popfl

/*
 * Copy the compressed kernel to the end of our buffer
 * where decompression in place becomes safe.
 */

/*
-------------------------------------------------------------------------
      ^        ^   alignment ^  z_extract_offset  ^ 未解压代码 ^     ^
  0x100000    _bss                                            _bss
     %ebp     %esi                               %ebx         %edi  %esp


*/

	/* esi内为全局变量boot_params的指针 */
	pushl	%esi
	leal	(_bss-4)(%ebp), %esi
	leal	(_bss-4)(%ebx), %edi
	/* 计算需要复制的字节数 */
	movl	$(_bss - startup_32), %ecx
	/* 除以4，每次是按4字节移动的 */
	shrl	$2, %ecx
	/* std: set direction flag
	   从后往前移动 */
	std
	/* 重复执行，开始复制代码 */
	rep	movsl
	cld
	/* 出栈，%esi依然指向全局变量boot_params */
	popl	%esi

/*
 * Jump to the relocated address.
 */
	/* 取得移动过后relocated的地址 */
	leal	relocated(%ebx), %eax
	/* call和jmp在操作数前指定前缀"*"，则表示是一个绝对地址跳转
	   如果没有"*"，则操作数是一个相对地址 */
	jmp	*%eax
ENDPROC(startup_32)

/*
根据连接脚本arch/x86/boot/compressed/vmlinux.lds
下面部分连接在压缩文件后的.text节
*/

	.text
relocated:

/*
 * Clear BSS (stack is currently empty)
 */
	xorl	%eax, %eax
	leal	_bss(%ebx), %edi
	leal	_ebss(%ebx), %ecx
	subl	%edi, %ecx
	/* 计算循环次数 */
	shrl	$2, %ecx
	/* 将%eax内的值，即0，存入%edi指向的空间，%edi默认使用附加段%es
	   达到bss清0的效果 */
	rep	stosl

/*
 * Adjust our own GOT
 */
/*
将%ebx中的值加到_got与_egot之间的每个值上
*/
	leal	_got(%ebx), %edx
	leal	_egot(%ebx), %ecx
1:
	cmpl	%ecx, %edx
	/* jae: jump if above or equel
	   作为循环结束的条件 */
	jae	2f
	/* 将值增加%ebs */
	addl	%ebx, (%edx)
	/* 每次循环后移4个字节 */
	addl	$4, %edx
	/* 循环，继续加 */
	jmp	1b
2:

/*
 * Do the decompression, and jump to the new kernel..
 */

/*
decompress_kernel()函数的定义:
asmlinkage void decompress_kernel(void *rmode, memptr heap,
				  unsigned char *input_data,
				  unsigned long input_len,
				  unsigned char *output)
在栈中准备decompress_kernel()函数的参数
然后调用decompress_kernel()函数

这里为函数传递的参数值
参考arch/x86/boot/compressed/mkpiggy.c
*/

/*
---------------------------------------------------------
      ^                  ^                ^ 未解压代码 ^
  0x100000             output             X
                        %ebp            %ebx

*/

	/* %ebx为临时的包含未解压代码的起始地址
	   %ebx减去增加的偏移，得到最终的解压地址 */
	leal	z_extract_offset_negative(%ebx), %ebp
				/* push arguments for decompress_kernel: */
	pushl	%ebp		/* output address */
	/* 压缩文件的大小，字节 */
	pushl	$z_input_len	/* input_len */
	/* 压缩文件的地址 */
	leal	input_data(%ebx), %eax
	pushl	%eax		/* input_data */
	/* 取boot_heap的物理地址 */
	leal	boot_heap(%ebx), %eax
	pushl	%eax		/* heap area */
	/* %esi内为全局变量boot_params的指针 */
	pushl	%esi		/* real mode pointer */

	/* 调用decompress_kernel()函数 */
	call	decompress_kernel

	/* 栈顶指针+20，即decompress_kernel()函数5个参数所占的长度
	   decompress_kernel()函数返回的时候退栈
	   栈是由高地址向低地址的，所以加20起到退栈的作用 */
	addl	$20, %esp

#if CONFIG_RELOCATABLE
/*
 * Find the address of the relocations.
 */
 	/* z_output_len为解压后文件的长度 */
	leal	z_output_len(%ebp), %edi

/*
 * Calculate the delta between where vmlinux was compiled to run
 * and where it was actually loaded.
 */
	movl	%ebp, %ebx
	/* %ebx - $LOAD_PHYSICAL_ADDR */
	subl	$LOAD_PHYSICAL_ADDR, %ebx
	/* 如果EFLAGS中的zero位为0
	   即2者相等的话，则什么也不用干，直接跳至标号2f处
	   否则就需要进行代码移动 */
	jz	2f	/* Nothing to be done if loaded at compiled addr. */
/*
 * Process relocations.
 */

	/* 递减，从后往前复制 */
1:	subl	$4, %edi
	movl	(%edi), %ecx
	testl	%ecx, %ecx
	jz	2f
	addl	%ebx, -__PAGE_OFFSET(%ebx, %ecx)
	jmp	1b
2:
#endif

/*
 * Jump to the decompressed kernel.
 */
	xorl	%ebx, %ebx
	/* 跳转到解压后的代码
	   arch/x86/kernel/head_32.S中的startup_32 */
	jmp	*%ebp

/*
 * Stack and heap for uncompression
 */
	.bss
	.balign 4
boot_heap:
	.fill BOOT_HEAP_SIZE, 1, 0
boot_stack:
	.fill BOOT_STACK_SIZE, 1, 0
boot_stack_end:

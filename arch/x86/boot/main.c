/* -*- linux-c -*- ------------------------------------------------------- *
 *
 *   Copyright (C) 1991, 1992 Linus Torvalds
 *   Copyright 2007 rPath, Inc. - All Rights Reserved
 *   Copyright 2009 Intel Corporation; author H. Peter Anvin
 *
 *   This file is part of the Linux kernel, and is made available under
 *   the terms of the GNU General Public License version 2.
 *
 * ----------------------------------------------------------------------- */

/*
 * Main module for the real-mode kernel code
 */

#include "boot.h"

struct boot_params boot_params __attribute__((aligned(16)));

/*
堆底
_end在arch/x86/boot/setup.ld中bss节上面
堆由低地址向高地址分配
*/
char *HEAP = _end;
/*
堆顶
初始化为_end
*/
char *heap_end = _end;		/* Default end of heap = no heap */

/*
 * Copy the header into the boot parameter block.  Since this
 * screws up the old-style command line protocol, adjust by
 * filling in the new-style command line pointer instead.
 */

/*
把第一扇区的参数复制到boot_params变量中
boot_params位于setup的数据段
*/
static void copy_boot_params(void)
{
	struct old_cmdline {
		u16 cl_magic;
		u16 cl_offset;
	};
	const struct old_cmdline * const oldcmd =
		(const struct old_cmdline *)OLD_CL_ADDRESS;

	/* 0页对应的struct boot_params结构大小正好为4096字节 */
	BUILD_BUG_ON(sizeof boot_params != 4096);
	/* 复制setup中的hdr信息
	   参考arch/x86/boot/header.S
	   arch/x86/include/asm/bootparam.h中的struct setup_header

	   到了这里便可以使用arch/x86/boot/printf.c中的printf()函数
	   将hdr各个字段的值打印出来查看了
	   例如: printf("hdr.code32_start:%x\n", hdr.code32_start);
	         查看32位代码在物理内存中的起始地址
			 对于bzImage便是0x100000了 */
	memcpy(&boot_params.hdr, &hdr, sizeof hdr);

	/* 如果bootloader没有传递命令行参数
	   则使用旧的协议地址 */
	if (!boot_params.hdr.cmd_line_ptr &&
	    oldcmd->cl_magic == OLD_CL_MAGIC) {
		/* Old-style command line protocol. */
		u16 cmdline_seg;

		/* Figure out if the command line falls in the region
		   of memory that an old kernel would have copied up
		   to 0x90000... */
		if (oldcmd->cl_offset < boot_params.hdr.setup_move_size)
			cmdline_seg = ds();
		else
			cmdline_seg = 0x9000;

		boot_params.hdr.cmd_line_ptr =
			(cmdline_seg << 4) + oldcmd->cl_offset;
	}
}

/*
 * Set the keyboard repeat rate to maximum.  Unclear why this
 * is done here; this might be possible to kill off as stale code.
 */
/*
stale: 过时的
*/
static void keyboard_set_repeat(void)
{
	struct biosregs ireg;
	initregs(&ireg);
	ireg.ax = 0x0305;
	intcall(0x16, &ireg, NULL);
}

/*
 * Get Intel SpeedStep (IST) information.
 */
/*
Speed Step是Intel CPU使用的一项技术，
在移动Pentium-3 600Mhz之后的移动版Pentium处理器中，
Intel加入了一个通过降低CPU运行主频来达到降低功耗的技术。
*/
static void query_ist(void)
{
	struct biosregs ireg, oreg;

	/* Some older BIOSes apparently crash on this call, so filter
	   it from machines too old to have SpeedStep at all. */
	if (cpu.level < 6)
		return;

	initregs(&ireg);
	ireg.ax  = 0xe980;	 /* IST Support */
	ireg.edx = 0x47534943;	 /* Request value */
	intcall(0x15, &ireg, &oreg);

	boot_params.ist_info.signature  = oreg.eax;
	boot_params.ist_info.command    = oreg.ebx;
	boot_params.ist_info.event      = oreg.ecx;
	boot_params.ist_info.perf_level = oreg.edx;
}

/*
 * Tell the BIOS what CPU mode we intend to run in.
 */
static void set_bios_mode(void)
{
#ifdef CONFIG_X86_64
	struct biosregs ireg;

	initregs(&ireg);
	ireg.ax = 0xec00;
	ireg.bx = 2;
	intcall(0x15, &ireg, NULL);
#endif
}

static void init_heap(void)
{
	char *stack_end;

	/* 如果CAN_USE_HEAP位置1了，说明heap_end_ptr中的值是有效的
	   参考boot.txt */
	if (boot_params.hdr.loadflags & CAN_USE_HEAP) {
		/* 取栈底指针 */
		asm("leal %P1(%%esp),%0"
		    : "=r" (stack_end) : "i" (-STACK_SIZE));

		/* 堆顶指针
		   加上0x200，因为bootloader中减了0x200，即去掉了第1个扇区
		   参考Documentation/x86/boot.txt */
		heap_end = (char *)
			((size_t)boot_params.hdr.heap_end_ptr + 0x200);
		/* 堆顶不能超过栈底 */
		if (heap_end > stack_end)
			heap_end = stack_end;
	} else {
		/* Boot protocol 2.00 only, no heap available */
		puts("WARNING: Ancient bootloader, some functionality "
		     "may be limited!\n");
	}
}

/*
main函数之后收集到的信息全部存放在setup的数据段中
*/
void main(void)
{
	/* First, copy the boot header into the "zeropage" */
	copy_boot_params();

	/* Initialize the early-boot console */
	console_init();
	/* 命令行中是否有debug */
	if (cmdline_find_option_bool("debug"))
		puts("early console in setup code\n");

	/* End of heap check */
	init_heap();

	/* Make sure we have all the proper CPU support */
	if (validate_cpu()) {
		puts("Unable to boot - please use a kernel appropriate "
		     "for your CPU.\n");
		die();
	}

	/* Tell the BIOS what CPU mode we intend to run in. */
	set_bios_mode();

	/* Detect memory layout */
	detect_memory();

	/* Set keyboard repeat rate (why?) */
	keyboard_set_repeat();

	/* Query MCA information */
	query_mca();

	/* Query Intel SpeedStep (IST) information */
	query_ist();

	/* Query APM information */
#if defined(CONFIG_APM) || defined(CONFIG_APM_MODULE)
	query_apm_bios();
#endif

	/* Query EDD information */
#if defined(CONFIG_EDD) || defined(CONFIG_EDD_MODULE)
	query_edd();
#endif

	/* Set the video mode */
	set_video();

	/* Do the last things and invoke protected mode */
	go_to_protected_mode();
}

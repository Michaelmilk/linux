/*
 *	header.S
 *
 *	Copyright (C) 1991, 1992 Linus Torvalds
 *
 *	Based on bootsect.S and setup.S
 *	modified by more people than can be counted
 *
 *	Rewritten as a common file by H. Peter Anvin (Apr 2007)
 *
 * BIG FAT NOTE: We''re in real mode using 64k segments.  Therefore segment
 * addresses must be multiplied by 16 to obtain their respective linear
 * addresses. To avoid confusion, linear addresses are written using leading
 * hex while segment addresses are written as segment:offset.
 *
 */

#include <asm/segment.h>
#include <generated/utsrelease.h>
#include <asm/boot.h>
#include <asm/e820.h>
#include <asm/page_types.h>
#include <asm/setup.h>
#include "boot.h"
#include "voffset.h"
#include "zoffset.h"

/*
16-bit实模式引导段地址，左移4位再加上偏移0
对应的线性地址就是0x7c00，即31K
此时是实模式，即物理地址
*/
BOOTSEG		= 0x07C0		/* original address of boot-sector */
/*
历史上system模块加载的段
即物理地址0x10000，即64K
*/
SYSSEG		= 0x1000		/* historical load address >> 4 */

/*
ASK_VGA参考Documentation/svga.txt
*/
#ifndef SVGA_MODE
#define SVGA_MODE ASK_VGA
#endif

#ifndef RAMDISK
#define RAMDISK 0
#endif

#ifndef ROOT_RDONLY
#define ROOT_RDONLY 1
#endif

	/* 连接的时候放在bstext节，boot sector
	   参考连接脚本setup.ld
	   使用objdump -d -M i8086 setup.elf查看其前面的内容
	   查看bzImage的二进制文件

	   使用code16告诉编译器，下面的代码要编译成16位代码
	   即编译成16位实模式代码 */
	.code16
	.section ".bstext", "ax"

	.global bootsect_start
bootsect_start:

	/* 当PC按下电源，CPU加电后，自动从0xFFFF0处开始执行代码，这个地址位于BIOS中。
	   接着BIOS开始一系列系统检测，并在内存物理地址0处初始化中断向量，
	   供Linux内核启动过程中进行调用。
	   此后，它将启动设备的第一个扇区（磁盘引导扇区，512Bytes）读入内存绝对地址0x7C00处，
	   并跳到这个地方开始执行。

	   此处第1条指令便进行长跳转到段0x07C0，偏移$start2处开始执行指令
	   实际上这部分指令已不会再使用
	   原来此处前512字节做的事已经由引导加载器来完成，如GRUB
	   参考grub代码中的boot/i386/pc/boot.S
	   内容存放在MBR内，读MBR内的512字节到物理地址0x7c00即stage1
	   可以使用dd if=dev/sda of=mbr.bin bs=512 count=1来查看当前硬盘的MBR内容

	   现在这部分代码由bootloader装入物理地址0x90000处，即576K
	   */
	# Normalize the start address
	ljmp	$BOOTSEG, $start2

start2:
	movw	%cs, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %ss
	xorw	%sp, %sp
	sti
	cld

	movw	$bugger_off_msg, %si

msg_loop:
	lodsb
	andb	%al, %al
	jz	bs_die
	movb	$0xe, %ah
	movw	$7, %bx
	int	$0x10
	jmp	msg_loop

bs_die:
	# Allow the user to press a key, then reboot
	xorw	%ax, %ax
	int	$0x16
	int	$0x19

	# int 0x19 should never return.  In case it does anyway,
	# invoke the BIOS reset code...
	ljmp	$0xf000,$0xfff0

	/* 查看bzImage的2进制文件，可以看到下面的这些字符 */
	.section ".bsdata", "a"
bugger_off_msg:
	.ascii	"Direct booting from floppy is no longer supported.\r\n"
	.ascii	"Please use a boot loader program instead.\r\n"
	.ascii	"\n"
	.ascii	"Remove disk and press any key to reboot . . .\r\n"
	.byte	0


	# Kernel attributes; used by setup.  This is part 1 of the
	# header, from the old boot sector.

/*
参考连接脚本setup.ld，header节从偏移497开始，即0x1F1
参考boot.txt
struct setup_header
*/
	.section ".header", "a"
	.globl	hdr
hdr:
/*
实模式setup代码所占扇区数，不包含这里的第1个扇区，512字节为单位
*/
setup_sects:	.byte 0			/* Filled in by build.c */
root_flags:	.word ROOT_RDONLY
syssize:	.long 0			/* Filled in by build.c */
ram_size:	.word 0			/* Obsolete */
vid_mode:	.word SVGA_MODE
root_dev:	.word 0			/* Filled in by build.c */
boot_flag:	.word 0xAA55

	# offset 512, entry point

/*
setup.bin的第2个512字节，偏移0x200
引导加载器切换回实模式后便跳转到此地址处开始执行
此处代码由引导加载器复制到物理地址X处
以X=0x90200为例，bootloader将ds寄存器设置为0x9000
*/
	.globl	_start
_start:
		# Explicitly enter this as bytes, or the assembler
		# tries to generate a 3-byte jump here, which causes
		# everything else to push off to the wrong offset.
		/* 进行硬编码，明确的使用字节写入跳转指令
		   否则汇编器会生成3个字节的跳转指令，便打乱了后面数据的偏移

		   0xeb即jmp指令的指令码
		   1f指向前1标号所对应的地址，这样便计算出了start_of_setup到此处的偏移
		   即跳转到start_of_setup处 */
		.byte	0xeb		# short (2-byte) jump
		.byte	start_of_setup-1f
1:

	# Part 2 of the header, from the old setup.S

		.ascii	"HdrS"		# header signature
		/* 协议版本2.10 */
		.word	0x020a		# header version number (>= 0x0105)
					# or else old loadlin-1.5 will fail)
		.globl realmode_swtch
realmode_swtch:	.word	0, 0		# default_switch, SETUPSEG
start_sys_seg:	.word	SYSSEG		# obsolete and meaningless, but just
					# in case something decided to "use" it
		.word	kernel_version-512 # pointing to kernel version string
					# above section of header is compatible
					# with loadlin-1.5 (header v1.5). Don''t
					# change it.

type_of_loader:	.byte	0		# 0 means ancient bootloader, newer
					# bootloaders know to change this.
					# See Documentation/i386/boot.txt for
					# assigned ids

# flags, unused bits must be zero (RFU) bit within loadflags
loadflags:
LOADED_HIGH	= 1			# If set, the kernel is loaded high
CAN_USE_HEAP	= 0x80			# If set, the loader also has set
					# heap_end_ptr to tell how much
					# space behind setup.S can be used for
					# heap purposes.
					# Only the loader knows what is free
		.byte	LOADED_HIGH

setup_move_size: .word  0x8000		# size to move, when setup is not
					# loaded at 0x90000. We will move setup
					# to 0x90000 then just before jumping
					# into the kernel. However, only the
					# loader knows how much data behind
					# us also needs to be loaded.

/*
bootloader加载bzImage第2部分代码的起始物理地址
*/
code32_start:				# here loaders can put a different
					# start address for 32-bit code.
		.long	0x100000	# 0x100000 = default for big kernel

ramdisk_image:	.long	0		# address of loaded ramdisk image
					# Here the loader puts the 32-bit
					# address where it loaded the image.
					# This only will be read by the kernel.

ramdisk_size:	.long	0		# its size in bytes

bootsect_kludge:
		.long	0		# obsolete

heap_end_ptr:	.word	_end+STACK_SIZE-512
					# (Header version 0x0201 or later)
					# space from here (exclusive) down to
					# end of setup code can be used by setup
					# for local heap purposes.

ext_loader_ver:
		.byte	0		# Extended boot loader version
ext_loader_type:
		.byte	0		# Extended boot loader type

cmd_line_ptr:	.long	0		# (Header version 0x0202 or later)
					# If nonzero, a 32-bit pointer
					# to the kernel command line.
					# The command line should be
					# located between the start of
					# setup and the end of low
					# memory (0xa0000), or it may
					# get overwritten before it
					# gets read.  If this field is
					# used, there is no longer
					# anything magical about the
					# 0x90000 segment; the setup
					# can be located anywhere in
					# low memory 0x10000 or higher.

ramdisk_max:	.long 0x7fffffff
					# (Header version 0x0203 or later)
					# The highest safe address for
					# the contents of an initrd
					# The current kernel allows up to 4 GB,
					# but leave it at 2 GB to avoid
					# possible bootloader bugs.

kernel_alignment:  .long CONFIG_PHYSICAL_ALIGN	#physical addr alignment
						#required for protected mode
						#kernel
#ifdef CONFIG_RELOCATABLE
relocatable_kernel:    .byte 1
#else
relocatable_kernel:    .byte 0
#endif
min_alignment:		.byte MIN_KERNEL_ALIGN_LG2	# minimum alignment
pad3:			.word 0

cmdline_size:   .long   COMMAND_LINE_SIZE-1     #length of the command line,
                                                #added with boot protocol
                                                #version 2.06

hardware_subarch:	.long 0			# subarchitecture, added with 2.07
						# default to 0 for normal x86 PC

hardware_subarch_data:	.quad 0

payload_offset:		.long ZO_input_data
payload_length:		.long ZO_z_input_len

setup_data:		.quad 0			# 64-bit physical pointer to
						# single linked list of
						# struct setup_data

pref_address:		.quad LOAD_PHYSICAL_ADDR	# preferred load addr

#define ZO_INIT_SIZE	(ZO__end - ZO_startup_32 + ZO_z_extract_offset)
#define VO_INIT_SIZE	(VO__end - VO__text)
#if ZO_INIT_SIZE > VO_INIT_SIZE
#define INIT_SIZE ZO_INIT_SIZE
#else
#define INIT_SIZE VO_INIT_SIZE
#endif
init_size:		.long INIT_SIZE		# kernel initialization size

# End of setup header #####################################################

/*
由0x200处直接跳转过来执行
初始化一些段寄存器后，设置实模式代码堆栈，bss清0，调用main.c中的main()函数
此时依然处于实模式
*/
	.section ".entrytext", "ax"

start_of_setup:

#ifdef SAFE_RESET_DISK_CONTROLLER
# Reset the disk controller.
	movw	$0x0000, %ax		# Reset disk controller
	movb	$0x80, %dl		# All disks
	int	$0x13
#endif

# Force %es = %ds
	/* grub跳转到_start时，ds内值为0x9000 */
	movw	%ds, %ax
	movw	%ax, %es
	cld

# Apparently some ancient versions of LILO invoked the kernel with %ss != %ds,
# which happened to work by accident for the old code.  Recalculate the stack
# pointer if %ss is invalid.  Otherwise leave it alone, LOADLIN sets up the
# stack behind its own code, so we can''t blindly put it directly past the heap.

	movw	%ss, %dx
	/* %dx - %ax 判断%ax与%dx是否相等
	   上面刚给%ax赋值为%ds
	   即判断%ss的值是否与%ds相等 */
	cmpw	%ax, %dx	# %ds == %ss?
	movw	%sp, %dx
	/* je: jump if equel
	   相等的话则跳到2f处
	   不相等的话则继续，设置堆栈指针 */
	je	2f		# -> assume %sp is reasonably set

/*

+---------------------+ <- %esp
|
|			<- heap_end_ptr
|
+---------------------+ <- _end
|
|
|			<- _start         0x90200
+---------------------+ <- bootsect_start 0x90000

*/

	# Invalid %ss, make up a new stack
	/* _end为setup.ld中bss节后面 */
	movw	$_end, %dx
	/* $CAN_USE_HEAP & loadflags 按位与，检查CAN_USE_HEAP位是否置位 */
	testb	$CAN_USE_HEAP, loadflags
	/* 如果ZF置位，即按位与的值为0，说明CAN_USE_HEAP没有置位
	   则heap_end_ptr不可用，所以跳过，到1f处 */
	jz	1f
	/* 取堆顶地址 */
	movw	heap_end_ptr, %dx
	/* 加上栈的大小 */
1:	addw	$STACK_SIZE, %dx
	/* jnc: jump if not carry
	   如果addw的结果没有产生进位的话，则跳转到2f处 */
	jnc	2f
	xorw	%dx, %dx	# Prevent wraparound

2:	# Now %dx should point to the end of our stack space
	/* andw: bitwise logical AND
	   按位与，以便4字节对齐 */
	andw	$~3, %dx	# dword align (might as well...)
	/* 栈顶指针有效的话则跳转到3f */
	jnz	3f
	/* 如果没有跳转3f的话，则将栈顶指向0xfffc，总之不能为0 */
	movw	$0xfffc, %dx	# Make sure we''re not zero
	/* 设置栈段
	   让%ds和%ss相等 */
3:	movw	%ax, %ss
	/* movzwl: move and zero extend
	   设置栈指针，高16位置0 */
	movzwl	%dx, %esp	# Clear upper half of %esp
	/* sti: set interrupt flag
	   设置中断标志，开启中断 */
	sti			# Now we should have a working stack

# We will have entered with %cs = %ds+0x20, normalize %cs so
# it is on par with the other segments.
/*
从grub中跳转到上面_start处时，cs寄存器内值为%ds+0x20
而本文件指令代码连接时是从0开始，为了得到正确的代码段基地址
这里利用ret指令重设cs和ip寄存器的值
*/
	/* grub跳转过来时，ds内值为0x9000
	   ds值入栈 */
	pushw	%ds
	/* 6f处地址入栈，6f值为链接文件中的相对偏移值 */
	pushw	$6f
	/* 使用ret指令返回到6f处
	   ret指令返回的时候会将栈中的值恢复到cs和ip寄存器中
	   这样cs寄存器的值便和ds寄存器的值相等了，均为0x9000
	   为setup指令在内存中的起始位置 */
	lretw
6:

# Check signature at end of setup
/*
检查setup的签名
setup_sig在连接脚本setup.ld中定义赋值
*/
	/* setup_sig - 0x5a5aaa55 相等的话即等于0
	   ZF置0 */
	cmpl	$0x5a5aaa55, setup_sig
	/* jne检查ZF是否为0，如果不为0的话，即不相等
	   则跳转到setup_bad */
	jne	setup_bad

# Zero the bss
/*
setup的bss段数据清0
*/
	movw	$__bss_start, %di
	movw	$_end+3, %cx
	/* 异或，eax清0 */
	xorl	%eax, %eax
	/* cx=cx-di 计算bss段长度 */
	subw	%di, %cx
	/* 逻辑右移2位，即除以4，将字节数转换为按照4字节单位计算
	   即使用ecx作为stosl的循环次数 */
	shrw	$2, %cx
	/* stosl的作用是将寄存器eax中的值保存到edi所指的单元中，即清0
	   然后移动edi指针到下一单元
	   rep使用ecx中的数做为循环计数器 */
	rep; stosl

# Jump to C code (should not return)
/*
调用arch/x86/boot/main.c中main()函数
main()中调用go_to_protected_mode() => protected_mode_jump()
跳转到保护模式代码
所以不会再返回这里
*/
	calll	main

# Setup corrupt somehow...
setup_bad:
	movl	$setup_corrupt, %eax
	calll	puts
	# Fall through...

	.globl	die
	.type	die, @function
die:
	hlt
	jmp	die

	.size	die, .-die

	.section ".initdata", "a"
setup_corrupt:
	.byte	7
	.string	"No setup signature found...\n"

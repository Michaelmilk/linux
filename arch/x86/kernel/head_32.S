/*
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Enhanced CPU detection and feature setting code by Mike Jagdis
 *  and Martin Mares, November 1997.
 */

/*
32位启动代码： 
编译程序在链接内核vmlinux的时候，将vmlinux起始位置链接到0xC0000000 + 0x100000，
这样所有的符号地址=0xC0000000+符号。在编译后的文件中的偏移地址。
因此在页面映射没有启动之前，如果需要访问符号的物理地址，必须要减去0xC0000000。

需要说明几点： 
1.内核vmlinux被加载的时候，其存放在物理地址为0x100000处。
CPU在执行这些指令的时候，如该文件中的第一条指令，CS=0,IP=0x100000，
由于该条指令的物理地址依然在0x100000，故CPU顺序往下执行，而无须程序作任何其他调整； 

2.但是，在链接vmlinux的时候，链接程序将该源程序中所有的符号，
例如符号empty_zero_page，在最后形成的二进制文件中都替换为固定的值，
这个固定的值就是：0xC0000000 + 0x100000 + 其在最后形成的二进制文件中的偏移 
这样在没有启动页面映射之前，如果直接访问该地址，由于该地址是在3G + offset，
在物理上基本上是不存在的，所以会出错。
为了访问到该符号所标识的数据所在的物理地址，需要减去0xC0000000，
这样便得到了该符号在该映射文件中的偏移值 + 0x100000，
由于内核在加载的时候刚好被加载在内存0x100000处，
故该符号在该映射文件中的偏移值+0x100000就是该符号在物理内存中的地址。 

在/arch/x86/kernel/vmlinux.lds.S中可以看到相关的设置信息，
objdump -D vmlinux命令来获取所有的符号以及这些符号的地址。

本文件为进入C语言编写的代码进行初始化
*/

.text
#include <linux/threads.h>
#include <linux/init.h>
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/page_types.h>
#include <asm/pgtable_types.h>
#include <asm/cache.h>
#include <asm/thread_info.h>
#include <asm/asm-offsets.h>
#include <asm/setup.h>
#include <asm/processor-flags.h>
#include <asm/msr-index.h>
#include <asm/cpufeature.h>
#include <asm/percpu.h>

/* Physical address */
/*
减去3G，将虚拟地址转换为物理地址
*/
#define pa(X) ((X) - __PAGE_OFFSET)

/*
 * References to members of the new_cpu_data structure.
 */

/*
new_cpu_data是类型为结构struct cpuinfo_x86的全局变量
在arch/i386/kernel/setup.c中定义
以下定义取的即是new_cpu_data中各字段的值

CPUINFO_x86各宏的定义在include/generated/asm-offsets.h中由Kbuild生成
*/

#define X86		new_cpu_data+CPUINFO_x86
#define X86_VENDOR	new_cpu_data+CPUINFO_x86_vendor
#define X86_MODEL	new_cpu_data+CPUINFO_x86_model
#define X86_MASK	new_cpu_data+CPUINFO_x86_mask
#define X86_HARD_MATH	new_cpu_data+CPUINFO_hard_math
#define X86_CPUID	new_cpu_data+CPUINFO_cpuid_level
#define X86_CAPABILITY	new_cpu_data+CPUINFO_x86_capability
#define X86_VENDOR_ID	new_cpu_data+CPUINFO_x86_vendor_id

/*
 * This is how much memory in addition to the memory covered up to
 * and including _end we need mapped initially.
 * We need:
 *     (KERNEL_IMAGE_SIZE/4096) / 1024 pages (worst case, non PAE)
 *     (KERNEL_IMAGE_SIZE/4096) / 512 + 4 pages (worst case for PAE)
 *
 * Modulo rounding, each megabyte assigned here requires a kilobyte of
 * memory, which is currently unreclaimed.
 *
 * This should be a multiple of a page.
 *
 * KERNEL_IMAGE_SIZE should be greater than pa(_end)
 * and small than max_low_pfn, otherwise will waste some page table entries
 */

#if PTRS_PER_PMD > 1
#define PAGE_TABLE_SIZE(pages) (((pages) / PTRS_PER_PMD) + PTRS_PER_PGD)
#else
/*
描述@pages需要的页表个数
*/
#define PAGE_TABLE_SIZE(pages) ((pages) / PTRS_PER_PGD)
#endif

/* Number of possible pages in the lowmem region */
/*
对于3G的偏移，内核直接访问的物理内存不超过1G，即256K个页框
*/
LOWMEM_PAGES = (((1<<32) - __PAGE_OFFSET) >> PAGE_SHIFT)
	
/* Enough space to fit pagetables for the low memory linear map */
/*
计算描述LOWMEM_PAGES所需的物理空间
*/
MAPPING_BEYOND_END = PAGE_TABLE_SIZE(LOWMEM_PAGES) << PAGE_SHIFT

/*
 * Worst-case size of the kernel mapping we need to make:
 * a relocatable kernel can live anywhere in lowmem, so we need to be able
 * to map all of lowmem.
 */
/*
因为内核会被重定向到896MB内存以下的任何位置
所以这里需要预先留出足够多的页表空间
*/
KERNEL_PAGES = LOWMEM_PAGES

/*
对于1GB内核空间，共有256K个页框
描述这么多的页框需要256个页表
每个页表占4KB，则共需要1MB的空间
*/
INIT_MAP_SIZE = PAGE_TABLE_SIZE(KERNEL_PAGES) * PAGE_SIZE
/*
预留堆空间
*/
RESERVE_BRK(pagetables, INIT_MAP_SIZE)

/*
 * 32-bit kernel entrypoint; only used by the boot CPU.  On entry,
 * %esi points to the real-mode code as a 32-bit pointer.
 * CS and DS must be 4 GB flat segments, but we don''t depend on
 * any particular GDT layout, because we load our own as soon as we
 * can.
 */

/*
ENTRY(name)宏展开为

.globl name;
ALIGN;
name:

.globl使得连接程序（ld）能够看到symbl。
如果局部程序中定义了symbl，那么，与这个局部程序连接的其他局部程序也能存取symbl
*/

/*
内核解压后从arch/x86/boot/compressed/head_32.S跳转而来
此处已经进入保护模式
*/
/*
在include/linux/init.h中定义
#define __HEAD		.section	".head.text","ax"
以下代码放在.head.text节
*/
__HEAD
ENTRY(startup_32)
	/* 把stack_start符号对应的物理地址处的4字节数放进ecx寄存器
	   %ecx指向内核栈底 */
	movl pa(stack_start),%ecx
	
	/* test KEEP_SEGMENTS flag to see if the bootloader is asking
		us to not reload segments */
	/* 检查引导参数是否置位了KEEP_SEGMENTS位 */
	testb $(1<<6), BP_loadflags(%esi)
	/* 如果置位了，则跳到标号2f
	   否则，继续，重新加载段寄存器 */
	jnz 2f

/*
 * Set segments to known values.
 */
/*
初始化保护模式下的各个段寄存器(还没有分页)
*/
	/* 将引导全局段描述符所处的物理地址加载到gdtr寄存器 */
	lgdt pa(boot_gdt_descr)
	/* 将__BOOT_DS的值加载进eax寄存器
	   引导代码段选择子 */
	movl $(__BOOT_DS),%eax
	movl %eax,%ds
	movl %eax,%es
	movl %eax,%fs
	movl %eax,%gs
	movl %eax,%ss
2:

/*
+-----------------------+ 8KB <- %esp
|			|
|			|
+-----------------------+ 4KB
|			|
|  struct thread_info 	| -> task
+-----------------------+ 0
*/
	/* 栈顶指针%esp指向stack_start */
	leal -__PAGE_OFFSET(%ecx),%esp

/*
 * Clear BSS first so that there are no surprises...
 */
/*
首先将内存BSS段对应物理地址中的值清0
*/
 	/* cld 清除方向标志 si di向前移动，增加
 	   std 设置方向 si di向后移动，减少 */
	cld
	/* 异或将eax寄存器清0 */
	xorl %eax,%eax
	/* BSS(Block Started by Symbol)通常是指
	   用来存放程序中未初始化的全局变量和静态变量的一块内存区域
	   将__bss_start物理地址放入edi寄存器 */
	movl $pa(__bss_start),%edi
	/* 将__bss_stop物理地址放入ecx寄存器 */
	movl $pa(__bss_stop),%ecx
	/* (ecx - edi)求出BSS段所占字节数，结果存入ecx寄存器 */
	subl %edi,%ecx
	/* 逻辑右移2位，即除以4，变成4字节单位 */
	shrl $2,%ecx
	/* rep 重复执行stosl，直到ecx寄存器的值为0
	   每执行一次rep，ecx寄存器中的值会减1，以便循环结束
	   stosl 以4字节单位把eax寄存器中的值(即0)写到edi寄存器中物理地址指向的内存中
	   上面使用了cld指令，edi中的值会步进4字节 */
	rep ; stosl
/*
 * Copy bootup parameters out of the way.
 * Note: %esi still has the pointer to the real-mode data.
 * With the kexec as boot loader, parameter segment might be loaded beyond
 * kernel image and might not even be addressable by early boot page tables.
 * (kexec on panic case). Hence copy out the parameters before initializing
 * page tables.
 */

/*
将setup部分arch/x86/boot/main.c的全局变量boot_params复制到
arch/x86/kernel/setup.c的全局变量boot_params中
*/
	movl $pa(boot_params),%edi
	/* struct boot_params的大小除以4放入ecx寄存器作为计数器 */
	movl $(PARAM_SIZE/4),%ecx
	cld
	rep
	movsl
	movl pa(boot_params) + NEW_CL_POINTER,%esi
	andl %esi,%esi
	jz 1f			# No command line
/*
将setup部分的命令行参数复制到init/main.c的全局变量boot_command_line中
*/
	/* %edi中为目的地址，即boot_command_line[COMMAND_LINE_SIZE]数组 */
	movl $pa(boot_command_line),%edi
	/* COMMAND_LINE_SIZE为字符数组boot_command_line的大小
	   除以4，以4字节为循环单位 */
	movl $(COMMAND_LINE_SIZE/4),%ecx
	rep
	/* 循环从%esi中复制命令行参数到%edi指向的地址中 */
	movsl
1:

#ifdef CONFIG_OLPC
	/* save OFW''s pgdir table for later use when calling into OFW */
	movl %cr3, %eax
	movl %eax, pa(olpc_ofw_pgd)
#endif

/*
 * Initialize page tables.  This creates a PDE and a set of page
 * tables, which are located immediately beyond __brk_base.  The variable
 * _brk_end is set up to point to the first "safe" location.
 * Mappings are created both at virtual address 0 (identity mapping)
 * and PAGE_OFFSET for up to _end.
 */
/*
初始化页表
*/
#ifdef CONFIG_X86_PAE

	/*
	 * In PAE mode initial_page_table is statically defined to contain
	 * enough entries to cover the VMSPLIT option (that is the top 1, 2 or 3
	 * entries). The identity mapping is handled by pointing two PGD entries
	 * to the first kernel PMD.
	 *
	 * Note the upper half of each PMD or PTE are always zero at this stage.
	 */

#define KPMDS (((-__PAGE_OFFSET) >> 30) & 3) /* Number of kernel PMDs */

	xorl %ebx,%ebx				/* %ebx is kept at zero */

	movl $pa(__brk_base), %edi
	movl $pa(initial_pg_pmd), %edx
	movl $PTE_IDENT_ATTR, %eax
10:
	leal PDE_IDENT_ATTR(%edi),%ecx		/* Create PMD entry */
	movl %ecx,(%edx)			/* Store PMD entry */
						/* Upper half already zero */
	addl $8,%edx
	movl $512,%ecx
11:
	stosl
	xchgl %eax,%ebx
	stosl
	xchgl %eax,%ebx
	addl $0x1000,%eax
	loop 11b

	/*
	 * End condition: we must map up to the end + MAPPING_BEYOND_END.
	 */
	movl $pa(_end) + MAPPING_BEYOND_END + PTE_IDENT_ATTR, %ebp
	cmpl %ebp,%eax
	jb 10b
1:
	addl $__PAGE_OFFSET, %edi
	movl %edi, pa(_brk_end)
	shrl $12, %eax
	movl %eax, pa(max_pfn_mapped)

	/* Do early initialization of the fixmap area */
	movl $pa(initial_pg_fixmap)+PDE_IDENT_ATTR,%eax
	movl %eax,pa(initial_pg_pmd+0x1000*KPMDS-8)
#else	/* Not PAE */

/*
3G的页目录项偏移
*/
page_pde_offset = (__PAGE_OFFSET >> 20);

/*
4KB的页

+---------------+ <- 4G
|		|
|		|
+---------------+ <- 3G page_pde_offset=3072 第768项
|		|
|		|
|		|
|		|
|		|
|		|
+---------------+ <- 0 第0项


物理内存布局
+---------------+
|		|
|		|
|		|
+---------------+ <- _end/__brk_limit
|		| <- _brk_end
|	.brk	|
+---------------+ <- __brk_base
|	.bss	|
+---------------+
|	.data	|
+---------------+
|	.text	|
+---------------+ 0x100000(或内核重定向的地址)
|		|
|		|
+---------------+


*/

	/* __brk_base的物理地址写入%edi寄存器 */
	movl $pa(__brk_base), %edi
	/* 页目录的物理地址 */
	movl $pa(initial_page_table), %edx
	/* 0x003 */
	movl $PTE_IDENT_ATTR, %eax
10:
	/* 0x067 */
	leal PDE_IDENT_ATTR(%edi),%ecx		/* Create PDE entry */
	/* 将值写入%edx中指针指向的物理地址处
	   即initial_page_table的第0项 */
	movl %ecx,(%edx)			/* Store identity PDE entry */
	/* initial_page_table的第768项中保存的指针值
	   指向__brk_base所在的页框 */
	movl %ecx,page_pde_offset(%edx)		/* Store kernel PDE entry */
	/* %edx加4，下面再次回跳到标号10处的时候
	   上面将设置第769项，依次类推 */
	addl $4,%edx
	/* 循环计数的次数 */
	movl $1024, %ecx
11:
	/* stosl: store doubleword string
	   将%eax中的值保存到ES:(E)DI指向的地址中
	   循环1024次，即设置4KB的大小，1个页表 */
	stosl
	/* 增加4K */
	addl $0x1000,%eax
	/* loop: loop with %ecx counter
	   循环1024次，设置1个页表中的1024项 */
	loop 11b
	/*
	 * End condition: we must map up to the end + MAPPING_BEYOND_END.
	 */
	/* 页表中映射的物理地址范围需要一直包含到下面这个值
	   即控制至少需要初始化的页表项数 */
	movl $pa(_end) + MAPPING_BEYOND_END + PTE_IDENT_ATTR, %ebp
	/* %eax - %ebp */
	cmpl %ebp,%eax
	/* jb: jump if below */
	jb 10b
	/* 加3G，转换为虚拟地址 */
	addl $__PAGE_OFFSET, %edi
	/* 给变量_brk_end赋值 */
	movl %edi, pa(_brk_end)
	/* 逻辑右移12bit */
	shrl $12, %eax
	/* 给变量max_pfn_mapped赋值
	   即页表中已经映射的物理页框数 */
	movl %eax, pa(max_pfn_mapped)

	/* Do early initialization of the fixmap area */
	/* initial_pg_fixmap对应页的物理地址存入页目录的最后一项 */
	movl $pa(initial_pg_fixmap)+PDE_IDENT_ATTR,%eax
	/* 0xffc=4092 即对应页目录的最后一项 */
	movl %eax,pa(initial_page_table+0xffc)
#endif

#ifdef CONFIG_PARAVIRT
	/* This is can only trip for a broken bootloader... */
	cmpw $0x207, pa(boot_params + BP_version)
	jb default_entry

	/* Paravirt-compatible boot parameters.  Look to see what architecture
		we''re booting under. */
	movl pa(boot_params + BP_hardware_subarch), %eax
	cmpl $num_subarch_entries, %eax
	jae bad_subarch

	movl pa(subarch_entries)(,%eax,4), %eax
	subl $__PAGE_OFFSET, %eax
	jmp *%eax

bad_subarch:
WEAK(lguest_entry)
WEAK(xen_entry)
	/* Unknown implementation; there's really
	   nothing we can do at this point. */
	ud2a

	__INITDATA

subarch_entries:
	.long default_entry		/* normal x86/PC */
	.long lguest_entry		/* lguest hypervisor */
	.long xen_entry			/* Xen hypervisor */
	.long default_entry		/* Moorestown MID */
num_subarch_entries = (. - subarch_entries) / 4
.previous
#else
	jmp default_entry
#endif /* CONFIG_PARAVIRT */

/*
 * Non-boot CPU entry point; entered from trampoline.S
 * We can''t lgdt here, because lgdt itself uses a data segment, but
 * we know the trampoline has already loaded the boot_gdt for us.
 *
 * If cpu hotplug is not supported then this code can go in init section
 * which will be freed later
 */

__CPUINIT

#ifdef CONFIG_SMP
ENTRY(startup_32_smp)
	cld
	/* 数据段选择子0x18 */
	movl $(__BOOT_DS),%eax
	movl %eax,%ds
	movl %eax,%es
	movl %eax,%fs
	movl %eax,%gs
	movl pa(stack_start),%ecx
	movl %eax,%ss
	leal -__PAGE_OFFSET(%ecx),%esp
#endif /* CONFIG_SMP */

/*
入口
*/
default_entry:

/*
 *	New page tables may be in 4Mbyte page mode and may
 *	be using the global pages. 
 *
 *	NOTE! If we are on a 486 we may have no cr4 at all!
 *	So we do not try to touch it unless we really have
 *	some bits in it to set.  This won''t work if the BSP
 *	implements cr4 but this AP does not -- very unlikely
 *	but be warned!  The same applies to the pse feature
 *	if not equally supported. --macro
 *
 *	NOTE! We have to correct for the fact that we''re
 *	not yet offset PAGE_OFFSET..
 */
#define cr4_bits pa(mmu_cr4_features)
	movl cr4_bits,%edx
	andl %edx,%edx
	/* 为0的话则跳转到标号6f处 */
	jz 6f
	movl %cr4,%eax		# Turn on paging options (PSE,PAE,..)
	orl %edx,%eax
	movl %eax,%cr4

	testb $X86_CR4_PAE, %al		# check if PAE is enabled
	jz 6f

	/* Check if extended functions are implemented */
	movl $0x80000000, %eax
	cpuid
	/* Value must be in the range 0x80000001 to 0x8000ffff */
	subl $0x80000001, %eax
	cmpl $(0x8000ffff-0x80000001), %eax
	ja 6f

	/* Clear bogus XD_DISABLE bits */
	call verify_cpu

	mov $0x80000001, %eax
	cpuid
	/* Execute Disable bit supported? */
	btl $(X86_FEATURE_NX & 31), %edx
	jnc 6f

	/* Setup EFER (Extended Feature Enable Register) */
	movl $MSR_EFER, %ecx
	rdmsr

	btsl $_EFER_NX, %eax
	/* Make changes effective */
	wrmsr

6:

/*
 * Enable paging
 */
/*
开启分页
*/
	/* 页目录表的物理地址 */
	movl $pa(initial_page_table), %eax
	/* cr3指向页目录表 */
	movl %eax,%cr3		/* set the page table pointer.. */
	/* cr0寄存器中，置位PG分页位，开启分页 */
	movl %cr0,%eax
	orl  $X86_CR0_PG,%eax
	movl %eax,%cr0		/* ..and set paging (PG) bit */
	/* 分页已经开启，使用长跳转
	   清预取的指令，并重值%eip */
	ljmp $__BOOT_CS,$1f	/* Clear prefetch and normalize %eip */
1:
	/* Shift the stack pointer to a virtual address */
	/* 已经开启分页了，所以栈顶指针不再直接使用物理地址
	   加上3G，转换为虚拟地址 */
	addl $__PAGE_OFFSET, %esp

/*
 * Initialize eflags.  Some BIOS''s leave bits like NT set.  This would
 * confuse the debugger if this code is traced.
 * XXX - best to initialize before switching to protected mode.
 */
	/* eflags寄存器清0 */
	pushl $0
	/* popfl: pop %eflags from stack */
	popfl

#ifdef CONFIG_SMP
	cmpb $0, ready
	jnz checkCPUtype
#endif /* CONFIG_SMP */

/*
 * start system 32-bit setup. We need to re-do some of the things done
 * in 16-bit mode for the "real" operations.
 */
	/* 设置中断描述符表 */
	call setup_idt

/*
检查CPU类型和各项参数
*/
checkCPUtype:

	movl $-1,X86_CPUID		#  -1 for no CPUID initially

/* check if it is 486 or 386. */
/*
 * XXX - this does a lot of unnecessary setup.  Alignment checks don''t
 * apply at our cpl of 0 and the stack ought to be aligned already, and
 * we don''t need to preserve eflags.
 */

	movb $3,X86		# at least 386
	pushfl			# push EFLAGS
	popl %eax		# get EFLAGS
	movl %eax,%ecx		# save original EFLAGS
	xorl $0x240000,%eax	# flip AC and ID bits in EFLAGS
	pushl %eax		# copy to EFLAGS
	popfl			# set EFLAGS
	pushfl			# get new EFLAGS
	popl %eax		# put it in eax
	xorl %ecx,%eax		# change in flags
	pushl %ecx		# restore original EFLAGS
	popfl
	testl $0x40000,%eax	# check if AC bit changed
	je is386

	movb $4,X86		# at least 486
	testl $0x200000,%eax	# check if ID bit changed
	je is486

	/* get vendor info */
	xorl %eax,%eax			# call CPUID with 0 -> return vendor ID
	cpuid
	movl %eax,X86_CPUID		# save CPUID level
	movl %ebx,X86_VENDOR_ID		# lo 4 chars
	movl %edx,X86_VENDOR_ID+4	# next 4 chars
	movl %ecx,X86_VENDOR_ID+8	# last 4 chars

	orl %eax,%eax			# do we have processor info as well?
	je is486

	movl $1,%eax		# Use the CPUID instruction to get CPU type
	cpuid
	movb %al,%cl		# save reg for future use
	andb $0x0f,%ah		# mask processor family
	movb %ah,X86
	andb $0xf0,%al		# mask model
	shrb $4,%al
	movb %al,X86_MODEL
	andb $0x0f,%cl		# mask mask revision
	movb %cl,X86_MASK
	movl %edx,X86_CAPABILITY

is486:	movl $0x50022,%ecx	# set AM, WP, NE and MP
	jmp 2f

is386:	movl $2,%ecx		# set MP
2:	movl %cr0,%eax
	andl $0x80000011,%eax	# Save PG,PE,ET
	orl %ecx,%eax
	movl %eax,%cr0

	call check_x87
	lgdt early_gdt_descr
	lidt idt_descr
	ljmp $(__KERNEL_CS),$1f
1:	movl $(__KERNEL_DS),%eax	# reload all the segment registers
	movl %eax,%ss			# after changing gdt.

	movl $(__USER_DS),%eax		# DS/ES contains default USER segment
	movl %eax,%ds
	movl %eax,%es

	movl $(__KERNEL_PERCPU), %eax
	movl %eax,%fs			# set this cpu''s percpu

#ifdef CONFIG_CC_STACKPROTECTOR
	/*
	 * The linker can''t handle this by relocation.  Manually set
	 * base address in stack canary segment descriptor.
	 */
	cmpb $0,ready
	jne 1f
	movl $gdt_page,%eax
	movl $stack_canary,%ecx
	movw %cx, 8 * GDT_ENTRY_STACK_CANARY + 2(%eax)
	shrl $16, %ecx
	movb %cl, 8 * GDT_ENTRY_STACK_CANARY + 4(%eax)
	movb %ch, 8 * GDT_ENTRY_STACK_CANARY + 7(%eax)
1:
#endif
	movl $(__KERNEL_STACK_CANARY),%eax
	movl %eax,%gs

	xorl %eax,%eax			# Clear LDT
	lldt %ax

	/* clear direction flag
	   DF置0，[SI]，[DI]执行增量操作 */
	cld			# gcc2 wants the direction flag cleared at all times
	pushl $0		# fake return address for unwinder
	movb $1, ready
	/* initial_code处保存的值为i386_start_kernel()函数的虚拟地址
	   call和jmp在操作数前指定前缀"*"，则表示是一个绝对地址跳转
	   如果没有"*"，则操作数是一个相对地址
	   调用arch/x86/kernel/head32.c中的i386_start_kernel()函数 */
	jmp *(initial_code)

/*
 * We depend on ET to be correct. This checks for 287/387.
 */
check_x87:
	movb $0,X86_HARD_MATH
	clts
	fninit
	fstsw %ax
	cmpb $0,%al
	je 1f
	movl %cr0,%eax		/* no coprocessor: have to set bits */
	xorl $4,%eax		/* set EM */
	movl %eax,%cr0
	ret
	ALIGN
1:	movb $1,X86_HARD_MATH
	.byte 0xDB,0xE4		/* fsetpm for 287, ignored by 387 */
	ret

/*
 *  setup_idt
 *
 *  sets up a idt with 256 entries pointing to
 *  ignore_int, interrupt gates. It doesn''t actually load
 *  idt - that can be done only after paging has been enabled
 *  and the kernel moved to PAGE_OFFSET. Interrupts
 *  are enabled elsewhere, when we can be relatively
 *  sure everything is ok.
 *
 *  Warning: %esi is live across this function.
 */

/*
 * 中断门描述符
 *
 * 31                          16                 7   4       0
 * ------------------------------------------------------------
 * |                             | |   | | | | | |   |        |
 * |       OFFSET 31...16        |P|DPL| |           |RESERVED|
 * |                             |1|00 |0|1|1|1|0|000|        |
 * ------------------------------------------------------------
 * |                             |                            |
 * |     SEGMENT SELECTOR        |       OFFSET 15..0         |
 * |                             |                            |
 * ------------------------------------------------------------
 */

setup_idt:
	/* 将ignore_int的虚拟地址加载进edx寄存器 */
	lea ignore_int,%edx
	movl $(__KERNEL_CS << 16),%eax
	movw %dx,%ax		/* selector = 0x0010 = cs */
	/* 0x8E00 = 1000111000000000 */
	movw $0x8E00,%dx	/* interrupt gate - dpl=0, present */

	/* 取idt_table的指针 */
	lea idt_table,%edi
	/* 循环256项 */
	mov $256,%ecx
rp_sidt:
	/* 低32位 */
	movl %eax,(%edi)
	/* 高32位 */
	movl %edx,4(%edi)
	/* 加8个字节，到下一项 */
	addl $8,%edi
	dec %ecx
	jne rp_sidt

.macro	set_early_handler handler,trapno
	lea \handler,%edx
	movl $(__KERNEL_CS << 16),%eax
	movw %dx,%ax
	movw $0x8E00,%dx	/* interrupt gate - dpl=0, present */
	lea idt_table,%edi
	movl %eax,8*\trapno(%edi)
	movl %edx,8*\trapno+4(%edi)
.endm

	/* 利用上面定义的宏，初始化几个异常的处理函数 */
	set_early_handler handler=early_divide_err,trapno=0
	set_early_handler handler=early_illegal_opcode,trapno=6
	set_early_handler handler=early_protection_fault,trapno=13
	set_early_handler handler=early_page_fault,trapno=14

	ret

early_divide_err:
	xor %edx,%edx
	pushl $0	/* fake errcode */
	jmp early_fault

early_illegal_opcode:
	movl $6,%edx
	pushl $0	/* fake errcode */
	jmp early_fault

early_protection_fault:
	movl $13,%edx
	jmp early_fault

early_page_fault:
	movl $14,%edx
	jmp early_fault

early_fault:
	cld
#ifdef CONFIG_PRINTK
	pusha
	movl $(__KERNEL_DS),%eax
	movl %eax,%ds
	movl %eax,%es
	cmpl $2,early_recursion_flag
	je hlt_loop
	incl early_recursion_flag
	movl %cr2,%eax
	pushl %eax
	pushl %edx		/* trapno */
	pushl $fault_msg
	call printk
#endif
	call dump_stack
hlt_loop:
	hlt
	jmp hlt_loop

/* This is the default interrupt "handler" :-) */
/*
默认的一个中断处理函数
该函数什么也不做
或许只会打印一些信息
*/
	ALIGN
ignore_int:
	cld
#ifdef CONFIG_PRINTK
	/* 调用printk()函数前，进行压栈处理 */
	pushl %eax
	pushl %ecx
	pushl %edx
	pushl %es
	pushl %ds
	movl $(__KERNEL_DS),%eax
	movl %eax,%ds
	movl %eax,%es
	cmpl $2,early_recursion_flag
	je hlt_loop
	incl early_recursion_flag
	pushl 16(%esp)
	pushl 24(%esp)
	pushl 32(%esp)
	pushl 40(%esp)
	/* 将提示信息压入栈中，做为参数传递给printk()函数 */
	pushl $int_msg
	call printk

	call dump_stack

	addl $(5*4),%esp
	/* 出栈，恢复各寄存器中的值 */
	popl %ds
	popl %es
	popl %edx
	popl %ecx
	popl %eax
#endif
	/* iret: return from interrupt */
	iret

#include "verify_cpu.S"

	__REFDATA
.align 4
ENTRY(initial_code)
	.long i386_start_kernel

/*
 * BSS section
 */
/*
在include/linux/linkage.h中__PAGE_ALIGNED_BSS定义为
#define __PAGE_ALIGNED_BSS	.section ".bss..page_aligned", "aw"
因此下面的数据放在连接脚本arch/x86/kernel/vmlinux.lds.S中的(.bss..page_aligned)节
*/
__PAGE_ALIGNED_BSS
	/* 按照页大小对齐，4KB */
	.align PAGE_SIZE
#ifdef CONFIG_X86_PAE
initial_pg_pmd:
	.fill 1024*KPMDS,4,0
#else
/*
初始的一个页目录
这里填充了4KB，内容全0
*/
ENTRY(initial_page_table)
	.fill 1024,4,0
#endif
initial_pg_fixmap:
	.fill 1024,4,0
ENTRY(empty_zero_page)
	.fill 4096,1,0
/*
内核页目录
即init进程(名称为swapper)的页目录
*/
ENTRY(swapper_pg_dir)
	.fill 1024,4,0

/*
 * This starts the data section.
 */
#ifdef CONFIG_X86_PAE
__PAGE_ALIGNED_DATA
	/* Page-aligned for the benefit of paravirt? */
	.align PAGE_SIZE
ENTRY(initial_page_table)
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR),0	/* low identity map */
# if KPMDS == 3
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR),0
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR+0x1000),0
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR+0x2000),0
# elif KPMDS == 2
	.long	0,0
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR),0
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR+0x1000),0
# elif KPMDS == 1
	.long	0,0
	.long	0,0
	.long	pa(initial_pg_pmd+PGD_IDENT_ATTR),0
# else
#  error "Kernel PMDs should be 1, 2 or 3"
# endif
	.align PAGE_SIZE		/* needs to be page-sized too */
#endif

.data
.balign 4
/*
init_thread_union定义在arch/x86/kernel/init_task.c中
占2个页空间，THREAD_SIZE为8KB
这样stack_start处的值即为内核栈底指针

+-----------------------+ 8KB <- stack_start中的值
|			|
|			|
+-----------------------+ 4KB
|			|
|  struct thread_info 	| -> task
+-----------------------+ 0

*/
ENTRY(stack_start)
	.long init_thread_union+THREAD_SIZE

early_recursion_flag:
	.long 0

ready:	.byte 0

int_msg:
	.asciz "Unknown interrupt or fault at: %p %p %p\n"

fault_msg:
/* fault info: */
	.ascii "BUG: Int %d: CR2 %p\n"
/* pusha regs: */
	.ascii "     EDI %p  ESI %p  EBP %p  ESP %p\n"
	.ascii "     EBX %p  EDX %p  ECX %p  EAX %p\n"
/* fault frame: */
	.ascii "     err %p  EIP %p   CS %p  flg %p\n"
	.ascii "Stack: %p %p %p %p %p %p %p %p\n"
	.ascii "       %p %p %p %p %p %p %p %p\n"
	.asciz "       %p %p %p %p %p %p %p %p\n"

#include "../../x86/xen/xen-head.S"

/*
 * The IDT and GDT 'descriptors' are a strange 48-bit object
 * only used by the lidt and lgdt instructions. They are not
 * like usual segment descriptors - they consist of a 16-bit
 * segment size, and 32-bit linear address value:
 */

.globl boot_gdt_descr
.globl idt_descr

	ALIGN
# early boot GDT descriptor (must use 1:1 address mapping)
	.word 0				# 32 bit align gdt_desc.address
boot_gdt_descr:
	.word __BOOT_DS+7
	.long boot_gdt - __PAGE_OFFSET

	.word 0				# 32-bit align idt_desc.address
idt_descr:
	.word IDT_ENTRIES*8-1		# idt contains 256 entries
	.long idt_table

# boot GDT descriptor (later on used by CPU#0):
	.word 0				# 32 bit align gdt_desc.address
ENTRY(early_gdt_descr)
	.word GDT_ENTRIES*8-1
	.long gdt_page			/* Overwritten for secondary CPUs */

/*
 * The boot_gdt must mirror the equivalent in setup.S and is
 * used only for booting.
 */
	.align L1_CACHE_BYTES
ENTRY(boot_gdt)
	/* 填充2项8个字节的段描述符，即引导代码段和引导数据段 */
	.fill GDT_ENTRY_BOOT_CS,8,0
	.quad 0x00cf9a000000ffff	/* kernel 4GB code at 0x00000000 */
	.quad 0x00cf92000000ffff	/* kernel 4GB data at 0x00000000 */

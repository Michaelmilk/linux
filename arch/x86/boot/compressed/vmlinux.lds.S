#include <asm-generic/vmlinux.lds.h>

OUTPUT_FORMAT(CONFIG_OUTPUT_FORMAT, CONFIG_OUTPUT_FORMAT, CONFIG_OUTPUT_FORMAT)

#undef i386

#include <asm/cache.h>
#include <asm/page_types.h>

/*
设置输出文件的体系架构
将ENTRY()中的符号的值设置成入口地址
*/
#ifdef CONFIG_X86_64
OUTPUT_ARCH(i386:x86-64)
ENTRY(startup_64)
#else
OUTPUT_ARCH(i386)
ENTRY(startup_32)
#endif

SECTIONS
{
	/* Be careful parts of head_64.S assume startup_32 is at
	 * address 0.
	 */
	. = 0;
	.head.text : {
		_head = . ;
		HEAD_TEXT
		_ehead = . ;
	}
	/* 连接压缩后的内核代码arch/x86/boot/compressed/vmlinux.bin.gz */
	.rodata..compressed : {
		*(.rodata..compressed)
	}
	/* 文本段 */
	.text :	{
		_text = .; 	/* Text */
		*(.text)
		*(.text.*)
		_etext = . ;
	}
	.rodata : {
		_rodata = . ;
		*(.rodata)	 /* read-only data */
		*(.rodata.*)
		_erodata = . ;
	}
	.got : {
		_got = .;
		KEEP(*(.got.plt))
		KEEP(*(.got))
		_egot = .;
	}
	.data :	{
		_data = . ;
		*(.data)
		*(.data.*)
		_edata = . ;
	}
	. = ALIGN(L1_CACHE_BYTES);
	.bss : {
		_bss = . ;
		*(.bss)
		*(.bss.*)
		*(COMMON)
		. = ALIGN(8);	/* For convenience during zeroing */
		_ebss = .;
	}
#ifdef CONFIG_X86_64
       . = ALIGN(PAGE_SIZE);
       .pgtable : {
		_pgtable = . ;
		*(.pgtable)
		_epgtable = . ;
	}
#endif
	_end = .;
}

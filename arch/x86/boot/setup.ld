/*
 * setup.ld
 *
 * Linker script for the i386 setup code
 */
OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(_start)

SECTIONS
{
	/* 链接脚本的起始地址为0
	   所以汇编代码部分需要注意ds等段寄存器的设置 */
	. = 0;
	/* boot sector text */
	.bstext		: { *(.bstext) }
	/* boot sector data */
	.bsdata		: { *(.bsdata) }

	. = 497;
	.header		: { *(.header) }
	.entrytext	: { *(.entrytext) }
	.inittext	: { *(.inittext) }
	.initdata	: { *(.initdata) }
	__end_init = .;

	.text		: { *(.text) }
	.text32		: { *(.text32) }

	. = ALIGN(16);
	.rodata		: { *(.rodata*) }

	.videocards	: {
		video_cards = .;
		*(.videocards)
		video_cards_end = .;
	}

	. = ALIGN(16);
	.data		: { *(.data*) }

	/* setup代码的签名，用于检查该代码是否被正确加载进了内存 */
	.signature	: {
		setup_sig = .;
		LONG(0x5a5aaa55)
	}


	. = ALIGN(16);
	.bss		:
	{
		__bss_start = .;
		*(.bss)
		__bss_end = .;
	}
	. = ALIGN(16);
	_end = .;

	/DISCARD/ : { *(.note*) }

	/*
	 * The ASSERT() sink to . is intentional, for binutils 2.14 compatibility:
	 */
	/* setup实模式代码最大32K */
	. = ASSERT(_end <= 0x8000, "Setup too big!");
	/* hdr必须在偏移0x1f1处 */
	. = ASSERT(hdr == 0x1f1, "The setup header has the wrong offset!");
	/* Necessary for the very-old-loader check to work... */
	. = ASSERT(__end_init <= 5*512, "init sections too big!");

}

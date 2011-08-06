/*
 * misc.c
 *
 * This is a collection of several routines from gzip-1.0.3
 * adapted for Linux.
 *
 * malloc by Hannu Savolainen 1993 and Matthias Urlichs 1994
 * puts by Nick Holloway 1993, better puts by Martin Mares 1995
 * High loaded stuff by Hans Lermen & Werner Almesberger, Feb. 1996
 */

#include "misc.h"

/* WARNING!!
 * This code is compiled with -fPIC and it is relocated dynamically
 * at run time, but no relocation processing is performed.
 * This means that it is not safe to place pointers in static structures.
 */

/*
 * Getting to provable safe in place decompression is hard.
 * Worst case behaviours need to be analyzed.
 * Background information:
 *
 * The file layout is:
 *    magic[2]
 *    method[1]
 *    flags[1]
 *    timestamp[4]
 *    extraflags[1]
 *    os[1]
 *    compressed data blocks[N]
 *    crc[4] orig_len[4]
 *
 * resulting in 18 bytes of non compressed data overhead.
 *
 * Files divided into blocks
 * 1 bit (last block flag)
 * 2 bits (block type)
 *
 * 1 block occurs every 32K -1 bytes or when there 50% compression
 * has been achieved. The smallest block type encoding is always used.
 *
 * stored:
 *    32 bits length in bytes.
 *
 * fixed:
 *    magic fixed tree.
 *    symbols.
 *
 * dynamic:
 *    dynamic tree encoding.
 *    symbols.
 *
 *
 * The buffer for decompression in place is the length of the
 * uncompressed data, plus a small amount extra to keep the algorithm safe.
 * The compressed data is placed at the end of the buffer.  The output
 * pointer is placed at the start of the buffer and the input pointer
 * is placed where the compressed data starts.  Problems will occur
 * when the output pointer overruns the input pointer.
 *
 * The output pointer can only overrun the input pointer if the input
 * pointer is moving faster than the output pointer.  A condition only
 * triggered by data whose compressed form is larger than the uncompressed
 * form.
 *
 * The worst case at the block level is a growth of the compressed data
 * of 5 bytes per 32767 bytes.
 *
 * The worst case internal to a compressed block is very hard to figure.
 * The worst case can at least be boundined by having one bit that represents
 * 32764 bytes and then all of the rest of the bytes representing the very
 * very last byte.
 *
 * All of which is enough to compute an amount of extra data that is required
 * to be safe.  To avoid problems at the block level allocating 5 extra bytes
 * per 32767 bytes of data is sufficient.  To avoind problems internal to a
 * block adding an extra 32767 bytes (the worst case uncompressed block size)
 * is sufficient, to ensure that in the worst case the decompressed data for
 * block will stop the byte before the compressed data for a block begins.
 * To avoid problems with the compressed data's meta information an extra 18
 * bytes are needed.  Leading to the formula:
 *
 * extra_bytes = (uncompressed_size >> 12) + 32768 + 18 + decompressor_size.
 *
 * Adding 8 bytes per 32K is a bit excessive but much easier to calculate.
 * Adding 32768 instead of 32767 just makes for round numbers.
 * Adding the decompressor_size is necessary as it musht live after all
 * of the data as well.  Last I measured the decompressor is about 14K.
 * 10K of actual data and 4K of bss.
 *
 */

/*
 * gzip declarations
 */
#define STATIC		static

#undef memset
#undef memcpy
#define memzero(s, n)	memset((s), 0, (n))


static void error(char *m);

/*
 * This is set up by the setup-routine at boot-time
 */
struct boot_params *real_mode;		/* Pointer to real-mode data */
static int quiet;
static int debug;

void *memset(void *s, int c, size_t n);
void *memcpy(void *dest, const void *src, size_t n);

#ifdef CONFIG_X86_64
#define memptr long
#else
#define memptr unsigned
#endif

static memptr free_mem_ptr;
static memptr free_mem_end_ptr;

static char *vidmem;
static int vidport;
static int lines, cols;

/*
注意:这里包含的是一个.c文件
文件内含有内核映像的解压函数gunzip()
*/
#ifdef CONFIG_KERNEL_GZIP
#include "../../../../lib/decompress_inflate.c"
#endif

#ifdef CONFIG_KERNEL_BZIP2
#include "../../../../lib/decompress_bunzip2.c"
#endif

#ifdef CONFIG_KERNEL_LZMA
#include "../../../../lib/decompress_unlzma.c"
#endif

#ifdef CONFIG_KERNEL_XZ
#include "../../../../lib/decompress_unxz.c"
#endif

#ifdef CONFIG_KERNEL_LZO
#include "../../../../lib/decompress_unlzo.c"
#endif

static void scroll(void)
{
	int i;

	memcpy(vidmem, vidmem + cols * 2, (lines - 1) * cols * 2);
	for (i = (lines - 1) * cols * 2; i < lines * cols * 2; i += 2)
		vidmem[i] = ' ';
}

#define XMTRDY          0x20

#define TXR             0       /*  Transmit register (WRITE) */
#define LSR             5       /*  Line Status               */
static void serial_putchar(int ch)
{
	unsigned timeout = 0xffff;

	while ((inb(early_serial_base + LSR) & XMTRDY) == 0 && --timeout)
		cpu_relax();

	outb(ch, early_serial_base + TXR);
}

void __putstr(int error, const char *s)
{
	int x, y, pos;
	char c;

#ifndef CONFIG_X86_VERBOSE_BOOTUP
	if (!error)
		return;
#endif
	if (early_serial_base) {
		const char *str = s;
		while (*str) {
			if (*str == '\n')
				serial_putchar('\r');
			serial_putchar(*str++);
		}
	}

	if (real_mode->screen_info.orig_video_mode == 0 &&
	    lines == 0 && cols == 0)
		return;

	x = real_mode->screen_info.orig_x;
	y = real_mode->screen_info.orig_y;

	while ((c = *s++) != '\0') {
		if (c == '\n') {
			x = 0;
			if (++y >= lines) {
				scroll();
				y--;
			}
		} else {
			vidmem[(x + cols * y) * 2] = c;
			if (++x >= cols) {
				x = 0;
				if (++y >= lines) {
					scroll();
					y--;
				}
			}
		}
	}

	real_mode->screen_info.orig_x = x;
	real_mode->screen_info.orig_y = y;

	pos = (x + cols * y) * 2;	/* Update cursor position */
	outb(14, vidport);
	outb(0xff & (pos >> 9), vidport+1);
	outb(15, vidport);
	outb(0xff & (pos >> 1), vidport+1);
}

void *memset(void *s, int c, size_t n)
{
	int i;
	char *ss = s;

	for (i = 0; i < n; i++)
		ss[i] = c;
	return s;
}
#ifdef CONFIG_X86_32
void *memcpy(void *dest, const void *src, size_t n)
{
	int d0, d1, d2;
	asm volatile(
		"rep ; movsl\n\t"
		"movl %4,%%ecx\n\t"
		"rep ; movsb\n\t"
		: "=&c" (d0), "=&D" (d1), "=&S" (d2)
		: "0" (n >> 2), "g" (n & 3), "1" (dest), "2" (src)
		: "memory");

	return dest;
}
#else
void *memcpy(void *dest, const void *src, size_t n)
{
	long d0, d1, d2;
	asm volatile(
		"rep ; movsq\n\t"
		"movq %4,%%rcx\n\t"
		"rep ; movsb\n\t"
		: "=&c" (d0), "=&D" (d1), "=&S" (d2)
		: "0" (n >> 3), "g" (n & 7), "1" (dest), "2" (src)
		: "memory");

	return dest;
}
#endif

static void error(char *x)
{
	__putstr(1, "\n\n");
	__putstr(1, x);
	__putstr(1, "\n\n -- System halted");

	while (1)
		asm("hlt");
}

static void parse_elf(void *output)
{
#ifdef CONFIG_X86_64
	Elf64_Ehdr ehdr;
	Elf64_Phdr *phdrs, *phdr;
#else
	Elf32_Ehdr ehdr;
	Elf32_Phdr *phdrs, *phdr;
#endif
	void *dest;
	int i;

	memcpy(&ehdr, output, sizeof(ehdr));
	if (ehdr.e_ident[EI_MAG0] != ELFMAG0 ||
	   ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
	   ehdr.e_ident[EI_MAG2] != ELFMAG2 ||
	   ehdr.e_ident[EI_MAG3] != ELFMAG3) {
		error("Kernel is not a valid ELF file");
		return;
	}

	if (!quiet)
		putstr("Parsing ELF... ");

	phdrs = malloc(sizeof(*phdrs) * ehdr.e_phnum);
	if (!phdrs)
		error("Failed to allocate space for phdrs");

	memcpy(phdrs, output + ehdr.e_phoff, sizeof(*phdrs) * ehdr.e_phnum);

	for (i = 0; i < ehdr.e_phnum; i++) {
		phdr = &phdrs[i];

		switch (phdr->p_type) {
		case PT_LOAD:
#ifdef CONFIG_RELOCATABLE
			dest = output;
			dest += (phdr->p_paddr - LOAD_PHYSICAL_ADDR);
#else
			dest = (void *)(phdr->p_paddr);
#endif
			memcpy(dest,
			       output + phdr->p_offset,
			       phdr->p_filesz);
			break;
		default: /* Ignore other PT_* */ break;
		}
	}
}

/*
asmlinkage通过堆栈传递参数
*/
asmlinkage void decompress_kernel(void *rmode, memptr heap,
				  unsigned char *input_data,
				  unsigned long input_len,
				  unsigned char *output)
{
	real_mode = rmode;

	if (cmdline_find_option_bool("quiet"))
		quiet = 1;
	if (cmdline_find_option_bool("debug"))
		debug = 1;

	if (real_mode->screen_info.orig_video_mode == 7) {
		/* 0xb0000 = 704K, 0x3b4 = 948 */
		vidmem = (char *) 0xb0000;
		vidport = 0x3b4;
	} else {
		/* 0xb8000 = 736K, 0x3d4 = 980 */
		vidmem = (char *) 0xb8000;
		vidport = 0x3d4;
	}

	lines = real_mode->screen_info.orig_video_lines;
	cols = real_mode->screen_info.orig_video_cols;

	console_init();
	if (debug)
		putstr("early console in decompress_kernel\n");

	free_mem_ptr     = heap;	/* Heap */
	free_mem_end_ptr = heap + BOOT_HEAP_SIZE;

	/* 判断对齐 */
	if ((unsigned long)output & (MIN_KERNEL_ALIGN - 1))
		error("Destination address inappropriately aligned");
#ifdef CONFIG_X86_64
	if (heap > 0x3fffffffffffUL)
		error("Destination address too large");
#else
	/* __PAGE_OFFSET通常为3G
	   -__PAGE_OFFSET即把最高位的1当成符号位，剩下的部分取反+1后即1G
	   128左移20位，即128M
	   计算下来即heap不能大于896M-1 */
	if (heap > ((-__PAGE_OFFSET-(128<<20)-1) & 0x7fffffff))
		error("Destination address too large");
#endif
#ifndef CONFIG_RELOCATABLE
	if ((unsigned long)output != LOAD_PHYSICAL_ADDR)
		error("Wrong destination address");
#endif

	if (!quiet)
		putstr("\nDecompressing Linux... ");
	/* 调用解压函数解压缩内核映像文件
	   当配置CONFIG_KERNEL_GZIP时，即decompress_inflate.c中的gunzip() */
	decompress(input_data, input_len, NULL, NULL, output, NULL, error);
	parse_elf(output);
	if (!quiet)
		putstr("done.\nBooting the kernel.\n");
	return;
}

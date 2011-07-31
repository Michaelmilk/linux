/* ----------------------------------------------------------------------- *
 *
 *  Copyright (C) 2009 Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License version
 *  2 as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *  02110-1301, USA.
 *
 *  H. Peter Anvin <hpa@linux.intel.com>
 *
 * ----------------------------------------------------------------------- */

/*
 * Compute the desired load offset from a compressed program; outputs
 * a small assembly wrapper with the appropriate symbols defined.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

/*
得到主机序保存的一个32位整数
@p	: 从p开始的是一个4字节整数，主机序存储
*/
static uint32_t getle32(const void *p)
{
	const uint8_t *cp = p;

	/* 低字节在前，逐个移位相加得到4字节整数的值 */
	return (uint32_t)cp[0] + ((uint32_t)cp[1] << 8) +
		((uint32_t)cp[2] << 16) + ((uint32_t)cp[3] << 24);
}

/*
使用mkpiggy程序把压缩过的vmlinux中的长度偏移信息提取出来，写入piggy.S
作为汇编的脚本进行编译
arch/x86/boot/compressed/mkpiggy
    arch/x86/boot/compressed/vmlinux.bin.gz > arch/x86/boot/compressed/piggy.S
*/
int main(int argc, char *argv[])
{
	uint32_t olen;
	long ilen;
	unsigned long offs;
	FILE *f;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s compressed_file\n", argv[0]);
		return 1;
	}

	/* Get the information for the compressed kernel image first */

	f = fopen(argv[1], "r");
	if (!f) {
		perror(argv[1]);
		return 1;
	}


	/* 把文件指针指向文件结束-4个字节处 */
	if (fseek(f, -4L, SEEK_END)) {
		perror(argv[1]);
	}

	/* 读取文件的最后4个字节内容 */
	if (fread(&olen, sizeof(olen), 1, f) != 1) {
		perror(argv[1]);
		return 1;
	}

	/* 通过文件指针的移动，这里便得到了压缩后文件的长度 */
	ilen = ftell(f);
	/* 压缩文件的最后4个字节保存的是原始文件的长度 */
	olen = getle32(&olen);
	fclose(f);

	/*
	 * Now we have the input (compressed) and output (uncompressed)
	 * sizes, compute the necessary decompression offset...
	 */

	offs = (olen > ilen) ? olen - ilen : 0;
	offs += olen >> 12;	/* Add 8 bytes for each 32K block */
	offs += 64*1024 + 128;	/* Add 64K + 128 bytes slack */
	offs = (offs+4095) & ~4095; /* Round to a 4K boundary */

	/* 向文件arch/x86/boot/compressed/piggy.S中写入以下内容 */
	printf(".section \".rodata..compressed\",\"a\",@progbits\n");
	printf(".globl z_input_len\n");
	printf("z_input_len = %lu\n", ilen);
	printf(".globl z_output_len\n");
	printf("z_output_len = %lu\n", (unsigned long)olen);
	printf(".globl z_extract_offset\n");
	printf("z_extract_offset = 0x%lx\n", offs);
	/* z_extract_offset_negative allows simplification of head_32.S */
	printf(".globl z_extract_offset_negative\n");
	printf("z_extract_offset_negative = -0x%lx\n", offs);

	printf(".globl input_data, input_data_end\n");
	printf("input_data:\n");
	/* 指示包含输入文件arch/x86/boot/compressed/vmlinux.bin.gz */
	printf(".incbin \"%s\"\n", argv[1]);
	printf("input_data_end:\n");

	/* 例如生成如下信息的piggy.S

		.section ".rodata..compressed","a",@progbits
		.globl z_input_len
		z_input_len = 2897101
		.globl z_output_len
		z_output_len = 6044700
		.globl z_extract_offset
		z_extract_offset = 0x311000
		.globl z_extract_offset_negative
		z_extract_offset_negative = -0x311000
		.globl input_data, input_data_end
		input_data:
		.incbin "arch/x86/boot/compressed/vmlinux.bin.gz"
		input_data_end:
	*/
	return 0;
}

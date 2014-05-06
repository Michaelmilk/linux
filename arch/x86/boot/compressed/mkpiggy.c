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
#include <tools/le_byteshift.h>

/*
ʹ��mkpiggy�����ѹ������vmlinux�еĳ���ƫ����Ϣ��ȡ������д��piggy.S
��Ϊ���Ľű����б���
arch/x86/boot/compressed/mkpiggy
    arch/x86/boot/compressed/vmlinux.bin.gz > arch/x86/boot/compressed/piggy.S
*/
int main(int argc, char *argv[])
{
	uint32_t olen;
	long ilen;
	unsigned long offs;
	FILE *f = NULL;
	int retval = 1;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s compressed_file\n", argv[0]);
		goto bail;
	}

	/* Get the information for the compressed kernel image first */

	f = fopen(argv[1], "r");
	if (!f) {
		perror(argv[1]);
		goto bail;
	}


	/* ���ļ�ָ��ָ���ļ�����-4���ֽڴ� */
	if (fseek(f, -4L, SEEK_END)) {
		perror(argv[1]);
	}

	/* ��ȡ�ļ������4���ֽ����� */
	if (fread(&olen, sizeof(olen), 1, f) != 1) {
		perror(argv[1]);
		goto bail;
	}

	/* ͨ���ļ�ָ����ƶ��������õ���ѹ�����ļ��ĳ��� */
	ilen = ftell(f);
	/* ѹ���ļ������4���ֽڱ������ԭʼ�ļ��ĳ��� */
	olen = get_unaligned_le32(&olen);

	/*
	 * Now we have the input (compressed) and output (uncompressed)
	 * sizes, compute the necessary decompression offset...
	 */

	offs = (olen > ilen) ? olen - ilen : 0;
	offs += olen >> 12;	/* Add 8 bytes for each 32K block */
	offs += 64*1024 + 128;	/* Add 64K + 128 bytes slack */
	/* ���뵽4K�߽� */
	offs = (offs+4095) & ~4095; /* Round to a 4K boundary */

	/* ���ļ�arch/x86/boot/compressed/piggy.S��д���������� */
	printf(".section \".rodata..compressed\",\"a\",@progbits\n");
	/* ѹ���ļ��Ĵ�С���ֽ� */
	printf(".globl z_input_len\n");
	printf("z_input_len = %lu\n", ilen);
	/* ��ѹ���ļ��Ĵ�С���ֽ� */
	printf(".globl z_output_len\n");
	printf("z_output_len = %lu\n", (unsigned long)olen);
	printf(".globl z_extract_offset\n");
	printf("z_extract_offset = 0x%lx\n", offs);
	/* z_extract_offset_negative allows simplification of head_32.S */
	printf(".globl z_extract_offset_negative\n");
	printf("z_extract_offset_negative = -0x%lx\n", offs);

	printf(".globl input_data, input_data_end\n");
	printf("input_data:\n");
	/* ָʾ���������ļ�arch/x86/boot/compressed/vmlinux.bin.gz */
	printf(".incbin \"%s\"\n", argv[1]);
	printf("input_data_end:\n");

	/* ��������������Ϣ��piggy.S

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

	retval = 0;
bail:
	if (f)
		fclose(f);
	return retval;
}

#!/bin/sh

# in = /.../linux/arch/x86/syscalls/syscall_32.tbl
# out = arch/x86/syscalls/../include/generated/uapi/asm/unistd_32.h
# my_abis = (i386)
# prefix = 
# offset = 
#
# in = /.../linux/arch/x86/syscalls/syscall_64.tbl
# out = arch/x86/syscalls/../include/generated/uapi/asm/unistd_64.h
# my_abis = i386
# prefix = (common|64)
# offset = 
#
# in = /.../linux/arch/x86/syscalls/syscall_32.tbl
# out = arch/x86/syscalls/../include/generated/uapi/asm/unistd_x32.h
# my_abis = (common|x32)
# prefix = 
# offset = __X32_SYSCALL_BIT
#
# in = /.../linux/arch/x86/syscalls/syscall_32.tbl
# out = arch/x86/syscalls/../include/generated/asm/unistd_32_ia32.h
# my_abis = (i386)
# prefix = ia32_
# offset = 
#
# in = /.../linux/arch/x86/syscalls/syscall_64.tbl
# out = arch/x86/syscalls/../include/generated/asm/unistd_64_x32.h
# my_abis = (x32)
# prefix = x32_
# offset = 

# Ϊ��3�������Ӹ����ţ�������','ת��Ϊ'|'

in="$1"
out="$2"
my_abis=`echo "($3)" | tr ',' '|'`
prefix="$4"
offset="$5"

# ����ͷ�ļ���ʿ������
# basename ȡ�ļ�����
# y ת���ַ�����Сдת��Ϊ��д
# s �滻�ִ�������ĸ�����滻Ϊ1���»��ߣ�2���»����滻Ϊ1���»���
#
# _ASM_X86_UNISTD_32_H
# _ASM_X86_UNISTD_64_H
# _ASM_X86_UNISTD_X32_H
# _ASM_X86_UNISTD_32_IA32_H
# _ASM_X86_UNISTD_64_X32_H
#
fileguard=_ASM_X86_`basename "$out" | sed \
    -e 'y/abcdefghijklmnopqrstuvwxyz/ABCDEFGHIJKLMNOPQRSTUVWXYZ/' \
    -e 's/[^A-Z0-9_]/_/g' -e 's/__/_/g'`

# �궨�壬ϵͳ���ú�
# -E ʹ����չ������ʽ
# [[:space:]] �ո��tab
# ƥ�������ֿ�ͷ+�հ�+i386��������
# ����ϵͳ���ú�����
# -z �ַ���Ϊnull
#
grep -E "^[0-9A-Fa-fXx]+[[:space:]]+${my_abis}" "$in" | sort -n | (
    echo "#ifndef ${fileguard}"
    echo "#define ${fileguard} 1"
    echo ""

    while read nr abi name entry ; do
	if [ -z "$offset" ]; then
	    echo "#define __NR_${prefix}${name} $nr"
	else
	    echo "#define __NR_${prefix}${name} ($offset + $nr)"
        fi
    done

    echo ""
    echo "#endif /* ${fileguard} */"
) > "$out"

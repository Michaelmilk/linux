#!/bin/sh

# ����ϵͳ���ñ�ͷ�ļ�
# ����������ļ�
#
# in = /.../linux/arch/x86/syscalls/syscall_32.tbl
# out = arch/x86/syscalls/../include/generated/asm/syscalls_32.h
#
# in = /.../linux/arch/x86/syscalls/syscall_64.tbl
# out = arch/x86/syscalls/../include/generated/asm/syscalls_64.h

in="$1"
out="$2"

# ƥ�������ֿ�ͷ
# ������������
# ��@abi��Ϊ��д
# -n �ַ�����Ϊnull
#
grep '^[0-9]' "$in" | sort -n | (
    while read nr abi name entry compat; do
	abi=`echo "$abi" | tr '[a-z]' '[A-Z]'`
	if [ -n "$compat" ]; then
	    echo "__SYSCALL_${abi}($nr, $entry, $compat)"
	elif [ -n "$entry" ]; then
	    echo "__SYSCALL_${abi}($nr, $entry, $entry)"
	fi
    done
) > "$out"

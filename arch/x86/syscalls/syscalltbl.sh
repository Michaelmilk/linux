#!/bin/sh

# 生成系统调用表头文件
# 输入与输出文件
#
# in = /.../linux/arch/x86/syscalls/syscall_32.tbl
# out = arch/x86/syscalls/../include/generated/asm/syscalls_32.h
#
# in = /.../linux/arch/x86/syscalls/syscall_64.tbl
# out = arch/x86/syscalls/../include/generated/asm/syscalls_64.h

in="$1"
out="$2"

# 匹配以数字开头
# 按照数字排序
# 把@abi变为大写
# -n 字符串不为null
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

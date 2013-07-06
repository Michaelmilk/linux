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

# 为第3个参数加个括号，并将其','转换为'|'

in="$1"
out="$2"
my_abis=`echo "($3)" | tr ',' '|'`
prefix="$4"
offset="$5"

# 生成头文件卫士的名称
# basename 取文件名称
# y 转换字符，将小写转换为大写
# s 替换字串，非字母数字替换为1个下划线，2个下划线替换为1个下划线
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

# 宏定义，系统调用号
# -E 使用扩展正则表达式
# [[:space:]] 空格或tab
# 匹配以数字开头+空白+i386这样的行
# 按照系统调用号排序
# -z 字符串为null
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

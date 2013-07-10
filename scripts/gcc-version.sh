#!/bin/sh
#
# gcc-version [-p] gcc-command
#
# Prints the gcc version of `gcc-command' in a canonical 4-digit form
# such as `0295' for gcc-2.95, `0303' for gcc-3.3, etc.
#
# With the -p option, prints the patchlevel as well, for example `029503' for
# gcc-2.95.3, `030301' for gcc-3.3.1, etc.
#

        # shift 对位置参数进行位移
        # 比如shift 3表示原来的$4现在变成$1，原来的$5现在变成$2等等，原来的$1、$2、$3丢弃，$0不移动。
        # 不带参数的shift命令相当于shift 1。
        # 这里既，若带-p参数，则忽略-p参数

if [ "$1" = "-p" ] ; then
	with_patchlevel=1;
	shift;
fi

        # $* shell所有的参数

compiler="$*"

        # 参数数量

if [ ${#compiler} -eq 0 ]; then
	echo "Error: No compiler specified."
	printf "Usage:\n\t$0 <gcc-command>\n"
	exit 1
fi

        # gcc主版本号
        # gcc次版本号
        # 补丁等级
        # 例如:gcc 4.7.2
        # 带参数-p则返回040702
        # 不带则返回0407

MAJOR=$(echo __GNUC__ | $compiler -E -x c - | tail -n 1)
MINOR=$(echo __GNUC_MINOR__ | $compiler -E -x c - | tail -n 1)
if [ "x$with_patchlevel" != "x" ] ; then
	PATCHLEVEL=$(echo __GNUC_PATCHLEVEL__ | $compiler -E -x c - | tail -n 1)
	printf "%02d%02d%02d\\n" $MAJOR $MINOR $PATCHLEVEL
else
	printf "%02d%02d\\n" $MAJOR $MINOR
fi

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

        # shift ��λ�ò�������λ��
        # ����shift 3��ʾԭ����$4���ڱ��$1��ԭ����$5���ڱ��$2�ȵȣ�ԭ����$1��$2��$3������$0���ƶ���
        # ����������shift�����൱��shift 1��
        # ����ȣ�����-p�����������-p����

if [ "$1" = "-p" ] ; then
	with_patchlevel=1;
	shift;
fi

        # $* shell���еĲ���

compiler="$*"

        # ��������

if [ ${#compiler} -eq 0 ]; then
	echo "Error: No compiler specified."
	printf "Usage:\n\t$0 <gcc-command>\n"
	exit 1
fi

        # gcc���汾��
        # gcc�ΰ汾��
        # �����ȼ�
        # ����:gcc 4.7.2
        # ������-p�򷵻�040702
        # �����򷵻�0407

MAJOR=$(echo __GNUC__ | $compiler -E -x c - | tail -n 1)
MINOR=$(echo __GNUC_MINOR__ | $compiler -E -x c - | tail -n 1)
if [ "x$with_patchlevel" != "x" ] ; then
	PATCHLEVEL=$(echo __GNUC_PATCHLEVEL__ | $compiler -E -x c - | tail -n 1)
	printf "%02d%02d%02d\\n" $MAJOR $MINOR $PATCHLEVEL
else
	printf "%02d%02d\\n" $MAJOR $MINOR
fi

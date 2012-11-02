#include <linux/bcd.h>
#include <linux/export.h>

/*
BCD: Binary-Coded Decimal
��4bit������������ʾ1��ʮ����������bcd�룬��-ʮ������
���õ���Ȩbcd��Ϊ8421��
*/
unsigned _bcd2bin(unsigned char val)
{
	return (val & 0x0f) + (val >> 4) * 10;
}
EXPORT_SYMBOL(_bcd2bin);

unsigned char _bin2bcd(unsigned val)
{
	return ((val / 10) << 4) + val % 10;
}
EXPORT_SYMBOL(_bin2bcd);

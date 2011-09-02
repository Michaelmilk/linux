#include <linux/bcd.h>
#include <linux/module.h>

/*
BCD: Binary-Coded Decimal
用4bit二进制数来表示1个十进制数，即bcd码，二-十进制码
常用的有权bcd码为8421码
*/
unsigned bcd2bin(unsigned char val)
{
	return (val & 0x0f) + (val >> 4) * 10;
}
EXPORT_SYMBOL(bcd2bin);

unsigned char bin2bcd(unsigned val)
{
	return ((val / 10) << 4) + val % 10;
}
EXPORT_SYMBOL(bin2bcd);

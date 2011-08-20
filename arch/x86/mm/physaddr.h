#include <asm/processor.h>

static inline int phys_addr_valid(resource_size_t addr)
{
#ifdef CONFIG_PHYS_ADDR_T_64BIT
	/* 检查地址@addr使用的bit位数是否超出cpu范围 */
	return !(addr >> boot_cpu_data.x86_phys_bits);
#else
	return 1;
#endif
}

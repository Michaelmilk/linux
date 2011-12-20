/*
 * Copyright (c) 2002-3 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 *
 * This file is released under the GPLv2
 */

#include <linux/device.h>
#include <linux/init.h>
#include <linux/memory.h>

#include "base.h"

/**
 * driver_init - initialize driver model.
 *
 * Call the driver model init functions to initialize their
 * subsystems. Called early from init/main.c.
 */
/*
初始化设备模型
*/
void __init driver_init(void)
{
	/* These are the core pieces */
	devtmpfs_init();
	/* sys/devices */
	devices_init();
	/* sys/bus */
	buses_init();
	/* sys/class */
	classes_init();
	/* sys/firmware */
	firmware_init();
	/* hypervisor:管理程序 */
	hypervisor_init();

	/* These are also core pieces, but must come after the
	 * core core pieces.
	 */
	platform_bus_init();
	system_bus_init();
	cpu_dev_init();
	memory_dev_init();
}

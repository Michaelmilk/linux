/*
 *	pci.h
 *
 *	PCI defines and function prototypes
 *	Copyright 1994, Drew Eckhardt
 *	Copyright 1997--1999 Martin Mares <mj@ucw.cz>
 *
 *	For more information, please consult the following manuals (look at
 *	http://www.pcisig.com/ for how to get them):
 *
 *	PCI BIOS Specification
 *	PCI Local Bus Specification
 *	PCI to PCI Bridge Specification
 *	PCI System Design Guide
 */

#ifndef LINUX_PCI_H
#define LINUX_PCI_H

#include <linux/pci_regs.h>	/* The pci register defines */

/*
 * The PCI interface treats multi-function devices as independent
 * devices.  The slot/function address of each device is encoded
 * in a single byte as follows:
 *
 *	7:3 = slot
 *	2:0 = function
 */
/* 把设备(5bit)和功能(3bit)合并进1个字节内 */
#define PCI_DEVFN(slot, func)	((((slot) & 0x1f) << 3) | ((func) & 0x07))
/* 设备 */
#define PCI_SLOT(devfn)		(((devfn) >> 3) & 0x1f)
/* 功能 */
#define PCI_FUNC(devfn)		((devfn) & 0x07)

/* Ioctls for /proc/bus/pci/X/Y nodes. */
#define PCIIOC_BASE		('P' << 24 | 'C' << 16 | 'I' << 8)
#define PCIIOC_CONTROLLER	(PCIIOC_BASE | 0x00)	/* Get controller for PCI device. */
#define PCIIOC_MMAP_IS_IO	(PCIIOC_BASE | 0x01)	/* Set mmap state to I/O space. */
#define PCIIOC_MMAP_IS_MEM	(PCIIOC_BASE | 0x02)	/* Set mmap state to MEM space. */
#define PCIIOC_WRITE_COMBINE	(PCIIOC_BASE | 0x03)	/* Enable/disable write-combining. */

#ifdef __KERNEL__

#include <linux/mod_devicetable.h>

#include <linux/types.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/list.h>
#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/kobject.h>
#include <linux/atomic.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/irqreturn.h>

/* Include the ID list */
#include <linux/pci_ids.h>

/* pci_slot represents a physical slot */
struct pci_slot {
	struct pci_bus *bus;		/* The bus this slot is on */
	struct list_head list;		/* node in list of slots on this bus */
	struct hotplug_slot *hotplug;	/* Hotplug info (migrate over time) */
	unsigned char number;		/* PCI_SLOT(pci_dev->devfn) */
	struct kobject kobj;
};

static inline const char *pci_slot_name(const struct pci_slot *slot)
{
	return kobject_name(&slot->kobj);
}

/* File state for mmap()s on /proc/bus/pci/X/Y */
enum pci_mmap_state {
	pci_mmap_io,
	pci_mmap_mem
};

/* This defines the direction arg to the DMA mapping routines. */
#define PCI_DMA_BIDIRECTIONAL	0
#define PCI_DMA_TODEVICE	1
#define PCI_DMA_FROMDEVICE	2
#define PCI_DMA_NONE		3

/*
 *  For PCI devices, the region numbers are assigned this way:
 */
enum {
	/* #0-5: standard PCI resources */
	PCI_STD_RESOURCES,
	PCI_STD_RESOURCE_END = 5,

	/* #6: expansion ROM resource */
	PCI_ROM_RESOURCE,

	/* device specific resources */
#ifdef CONFIG_PCI_IOV
	PCI_IOV_RESOURCES,
	PCI_IOV_RESOURCE_END = PCI_IOV_RESOURCES + PCI_SRIOV_NUM_BARS - 1,
#endif

	/* resources assigned to buses behind the bridge */
#define PCI_BRIDGE_RESOURCE_NUM 4

	PCI_BRIDGE_RESOURCES,
	PCI_BRIDGE_RESOURCE_END = PCI_BRIDGE_RESOURCES +
				  PCI_BRIDGE_RESOURCE_NUM - 1,

	/* total resources associated with a PCI device */
	PCI_NUM_RESOURCES,

	/* preserve this for compatibility */
	DEVICE_COUNT_RESOURCE
};

typedef int __bitwise pci_power_t;

/* D0 : Fully-On 正常工作状态 */
#define PCI_D0		((pci_power_t __force) 0)
/* D1 D2 : 中间电源状态，根据设备不同而有所不同 */
#define PCI_D1		((pci_power_t __force) 1)
#define PCI_D2		((pci_power_t __force) 2)
#define PCI_D3hot	((pci_power_t __force) 3)
#define PCI_D3cold	((pci_power_t __force) 4)
#define PCI_UNKNOWN	((pci_power_t __force) 5)
#define PCI_POWER_ERROR	((pci_power_t __force) -1)

/* Remember to update this when the list above changes! */
extern const char *pci_power_names[];

static inline const char *pci_power_name(pci_power_t state)
{
	return pci_power_names[1 + (int) state];
}

#define PCI_PM_D2_DELAY	200
#define PCI_PM_D3_WAIT	10
#define PCI_PM_BUS_WAIT	50

/** The pci_channel state describes connectivity between the CPU and
 *  the pci device.  If some PCI bus between here and the pci device
 *  has crashed or locked up, this info is reflected here.
 */
typedef unsigned int __bitwise pci_channel_state_t;

enum pci_channel_state {
	/* I/O channel is in normal state */
	pci_channel_io_normal = (__force pci_channel_state_t) 1,

	/* I/O to channel is blocked */
	pci_channel_io_frozen = (__force pci_channel_state_t) 2,

	/* PCI card is dead */
	pci_channel_io_perm_failure = (__force pci_channel_state_t) 3,
};

typedef unsigned int __bitwise pcie_reset_state_t;

enum pcie_reset_state {
	/* Reset is NOT asserted (Use to deassert reset) */
	pcie_deassert_reset = (__force pcie_reset_state_t) 1,

	/* Use #PERST to reset PCI-E device */
	pcie_warm_reset = (__force pcie_reset_state_t) 2,

	/* Use PCI-E Hot Reset to reset device */
	pcie_hot_reset = (__force pcie_reset_state_t) 3
};

typedef unsigned short __bitwise pci_dev_flags_t;
enum pci_dev_flags {
	/* INTX_DISABLE in PCI_COMMAND register disables MSI
	 * generation too.
	 */
	PCI_DEV_FLAGS_MSI_INTX_DISABLE_BUG = (__force pci_dev_flags_t) 1,
	/* Device configuration is irrevocably lost if disabled into D3 */
	PCI_DEV_FLAGS_NO_D3 = (__force pci_dev_flags_t) 2,
	/* Provide indication device is assigned by a Virtual Machine Manager */
	PCI_DEV_FLAGS_ASSIGNED = (__force pci_dev_flags_t) 4,
};

enum pci_irq_reroute_variant {
	INTEL_IRQ_REROUTE_VARIANT = 1,
	MAX_IRQ_REROUTE_VARIANTS = 3
};

typedef unsigned short __bitwise pci_bus_flags_t;
enum pci_bus_flags {
	PCI_BUS_FLAGS_NO_MSI   = (__force pci_bus_flags_t) 1,
	PCI_BUS_FLAGS_NO_MMRBC = (__force pci_bus_flags_t) 2,
};

/* Based on the PCI Hotplug Spec, but some values are made up by us */
enum pci_bus_speed {
	PCI_SPEED_33MHz			= 0x00,
	PCI_SPEED_66MHz			= 0x01,
	PCI_SPEED_66MHz_PCIX		= 0x02,
	PCI_SPEED_100MHz_PCIX		= 0x03,
	PCI_SPEED_133MHz_PCIX		= 0x04,
	PCI_SPEED_66MHz_PCIX_ECC	= 0x05,
	PCI_SPEED_100MHz_PCIX_ECC	= 0x06,
	PCI_SPEED_133MHz_PCIX_ECC	= 0x07,
	PCI_SPEED_66MHz_PCIX_266	= 0x09,
	PCI_SPEED_100MHz_PCIX_266	= 0x0a,
	PCI_SPEED_133MHz_PCIX_266	= 0x0b,
	AGP_UNKNOWN			= 0x0c,
	AGP_1X				= 0x0d,
	AGP_2X				= 0x0e,
	AGP_4X				= 0x0f,
	AGP_8X				= 0x10,
	PCI_SPEED_66MHz_PCIX_533	= 0x11,
	PCI_SPEED_100MHz_PCIX_533	= 0x12,
	PCI_SPEED_133MHz_PCIX_533	= 0x13,
	PCIE_SPEED_2_5GT		= 0x14,
	PCIE_SPEED_5_0GT		= 0x15,
	PCIE_SPEED_8_0GT		= 0x16,
	PCI_SPEED_UNKNOWN		= 0xff,
};

struct pci_cap_saved_data {
	char cap_nr;
	unsigned int size;
	u32 data[0];
};

struct pci_cap_saved_state {
	struct hlist_node next;
	struct pci_cap_saved_data cap;
};

struct pcie_link_state;
struct pci_vpd;
struct pci_sriov;
struct pci_ats;

/*
 * The pci_dev structure is used to describe PCI devices.
 */
/*
PCI是一个总线标准，PCI总线上的设备就是PCI设备，
这些设备有很多类型，当然也包括网卡设备，
每一个PCI设备在内核中抽象为一个数据结构pci_dev,它描述了一个PCI设备的所有的特性

PCI设备主要包括两类空间，
一个是配置空间，它是操作系统或BIOS控制外设的统一格式的空间，
CPU指令不能访问，访问这个空间要借助BIOS功能，
事实上Linux的访问配置空间的函数是通过CPU指令驱使BIOS来完成读写访问的。
另一类是普通的控制寄存器空间，这一部分映射完后CPU可以访问来控制设备工作。

pci设备和pci驱动没有直接使用device和device_driver，
而是将二者封装起来，加上pci特定信息构成pci_dev和pci_driver。

PCI设备的发现是通过特定代码探测PCI空间来实现的。
PCI设备由内核自动生成的。
这样在注册pci驱动的时候PCI设备已经注册，其属性如ID的信息都已经是被初始化好了。
*/
struct pci_dev {
	/* 总线设备链表元素bus_list:
	   每一个pci_dev结构除了链接到全局设备链表中外，
	   还会通过这个成员连接到其所属PCI总线的设备链表中。
	   每一条PCI总线都维护一条它自己的设备链表视图，
	   以便描述所有连接在该PCI总线上的设备，
	   其表头由PCI总线的pci_bus结构中的 devices成员所描述。
           不要被bus_list名称迷惑，可不是总线链表的意思，pci_dev使用此节点将自身加入到
           其所在总线pci_bus的成员devices描述的头节点链表中
	*/
	struct list_head bus_list;	/* node in per-bus list */
	/* 总线指针bus:指向这个PCI设备所在的PCI总线的pci_bus结构。
	   因此，对于桥设备而言，bus指针将指向桥设备的主总线(primary bus)，
	   也即指向桥设备所在的PCI总线。
	*/
	struct pci_bus	*bus;		/* bus this device is on */
	/* 指针subordinate:指向这个PCI设备所桥接的下级总线。
	   这个指针成员仅对桥设备才有意义，而对于一般的非桥PCI设备而言，
	   该指针成员总是为NULL。
	*/
	struct pci_bus	*subordinate;	/* bus this device bridges to */

	/* 无类型指针sysdata:指向一片特定于系统的扩展数据。 */
	void		*sysdata;	/* hook for sys-specific extension */
	/* 指针procent:指向该PCI设备在/proc文件系统中对应的目录项。 */
	struct proc_dir_entry *procent;	/* device entry in /proc/bus/pci */
	struct pci_slot	*slot;		/* Physical slot this device is in */

	/* devfn:这个PCI设备的设备功能号，
	   也成为PCI逻辑设备号(0－255)。
	   其中bit[7-3]是物理设备号(取值范围0-31)，
	   bit[2-0]是功能号(取值范围0-7)。
	*/
	unsigned int	devfn;		/* encoded device & function index */
	/* vendor:这是一个16位无符号整数，表示PCI设备的厂商ID。 */
	unsigned short	vendor;
	/* device:这是一个16位无符号整数，表示PCI设备的设备ID。 */
	unsigned short	device;
	/* subsystem_vendor:这是一个16位无符号整数，表示PCI设备的子系统厂商ID。 */
	unsigned short	subsystem_vendor;
	/* subsystem_device:这是一个16位无符号整数，表示PCI设备的子系统设备ID。 */
	unsigned short	subsystem_device;
	/* class:32位的无符号整数，表示该PCI设备的类别，
	   其中，bit[7-0]为编程接口，
	   bit[15-8]为子类别代码，
	   bit[23-16]为基类别代码，
	   bit[31-24]无意义。
	   显然，class成员的低3字节刚好对应与PCI配置空间中的类代码。
	*/
	unsigned int	class;		/* 3 bytes: (base,sub,prog-if) */
	u8		revision;	/* PCI revision, low byte of class word */
	/* hdr_type:8位无符号整数，表示PCI配置空间头部的类型。
	   其中，bit[7]=1表示这是一个多功能设备，bit[7]=0表示这是一个单功能设备。
	   Bit[6-0]则表示PCI配置空间头部的布局类型，
	   值00h表示这是一个一般PCI设备的配置空间头部，
	   值01h表示这是一个PCI-to-PCI桥的配置空间头部，
	   值02h表示CardBus桥的配置空间头部。
	*/
	u8		hdr_type;	/* PCI header type (`multi' flag masked out) */
	u8		pcie_cap;	/* PCI-E capability offset */
	u8		pcie_type:4;	/* PCI-E device/port type */
	u8		pcie_mpss:3;	/* PCI-E Max Payload Size Supported */
	/* rom_base_reg:8位无符号整数，
	   表示PCI配置空间中的ROM基地址寄存器在PCI配置空间中的位置。
	   ROM基地址寄存器在不同类型的PCI配置空间头部的位置是不一样的，
	   对于type 0的配置空间布局，ROM基地址寄存器的起始位置是30h，
	   而对于PCI-to-PCI桥所用的type 1配置空间布局，ROM基地址寄存器的起始位置是38h。
	*/
	u8		rom_base_reg;	/* which config register controls the ROM */
	u8		pin;  		/* which interrupt pin this device uses */

	/* 指针driver:指向这个PCI设备所对应的驱动程序定义的pci_driver结构。
	   每一个pci设备驱动程序都必须定义它自己的pci_driver结构来描述它自己。
	*/
	struct pci_driver *driver;	/* which driver has allocated this device */
	/* dma_mask:用于DMA的总线地址掩码，一般来说，这个成员的值是0xffffffff。
	   数据类型dma_addr_t定义在include/asm/types.h中，
	   在x86平台上，dma_addr_t类型就是u32类型。
	*/
	u64		dma_mask;	/* Mask of the bits of bus address this
					   device implements.  Normally this is
					   0xffffffff.  You only need to change
					   this if your device has broken DMA
					   or supports 64-bit transfers.  */

	struct device_dma_parameters dma_parms;

	pci_power_t     current_state;  /* Current operating state. In ACPI-speak,
					   this is D0-D3, D0 being fully functional,
					   and D3 being off. */
	int		pm_cap;		/* PM capability offset in the
					   configuration space */
	unsigned int	pme_support:5;	/* Bitmask of states from which PME#
					   can be generated */
	unsigned int	pme_interrupt:1;
	unsigned int	pme_poll:1;	/* Poll device's PME status bit */
	unsigned int	d1_support:1;	/* Low power state D1 is supported */
	unsigned int	d2_support:1;	/* Low power state D2 is supported */
	unsigned int	no_d1d2:1;	/* Only allow D0 and D3 */
	unsigned int	mmio_always_on:1;	/* disallow turning off io/mem
						   decoding during bar sizing */
	unsigned int	wakeup_prepared:1;
	unsigned int	d3_delay;	/* D3->D0 transition time in ms */

#ifdef CONFIG_PCIEASPM
	struct pcie_link_state	*link_state;	/* ASPM link state. */
#endif

	pci_channel_state_t error_state;	/* current connectivity state */
	/* 内嵌的通用设备结构，设备自身 */
	struct	device	dev;		/* Generic device interface */

	int		cfg_size;	/* Size of configuration space */

	/*
	 * Instead of touching interrupt line and base address registers
	 * directly, use the values stored here. They might be different!
	 */
	unsigned int	irq;
	/* 资源数组resource[DEVICE_COUNT_RESOURCE]:
	   表示该设备可能用到的资源，
	   包括:I/O断口区域、设备内存地址区域以及扩展ROM地址区域。
	   根据pci.h头文件中枚举的定义，DEVICE_COUNT_RESOURCE为12
	   但是PCI设备通常仅使用这12个资源区域中的一部分。
	   其中，resource[5-0]分别对应于配置空间中的BAR0-BAR5(注意，桥设备只有BAR0和BAR1)
	   resource[6]对应于配置空间中的ROM基地址寄存器所描述的ROM区域，
	   而resource[10-7]分别对应于桥设备的地址过滤窗口。
	*/
	struct resource resource[DEVICE_COUNT_RESOURCE]; /* I/O and memory regions + expansion ROMs */
	resource_size_t	fw_addr[DEVICE_COUNT_RESOURCE]; /* FW-assigned addr */

	/* These fields are used by common fixups */
	unsigned int	transparent:1;	/* Transparent PCI bridge */
	/* 多功能设备，比如USB控制器 */
	unsigned int	multifunction:1;/* Part of multi-function device */
	/* keep track of device state */
	unsigned int	is_added:1;
	unsigned int	is_busmaster:1; /* device is busmaster */
	unsigned int	no_msi:1;	/* device may not use msi */
	unsigned int	block_ucfg_access:1;	/* userspace config space access is blocked */
	unsigned int	broken_parity_status:1;	/* Device generates false positive parity */
	unsigned int	irq_reroute_variant:2;	/* device needs IRQ rerouting variant */
	/* Message Signaled Interrupts 消息中断 */
	unsigned int 	msi_enabled:1;
	unsigned int	msix_enabled:1;
	unsigned int	ari_enabled:1;	/* ARI forwarding */
	unsigned int	is_managed:1;
	unsigned int	is_pcie:1;	/* Obsolete. Will be removed.
					   Use pci_is_pcie() instead */
	unsigned int    needs_freset:1; /* Dev requires fundamental reset */
	unsigned int	state_saved:1;
	unsigned int	is_physfn:1;
	unsigned int	is_virtfn:1;
	unsigned int	reset_fn:1;
	unsigned int    is_hotplug_bridge:1;
	unsigned int    __aer_firmware_first_valid:1;
	unsigned int	__aer_firmware_first:1;
	pci_dev_flags_t dev_flags;
	atomic_t	enable_cnt;	/* pci_enable_device has been called */

	u32		saved_config_space[16]; /* config space saved at suspend time */
	struct hlist_head saved_cap_space;
	struct bin_attribute *rom_attr; /* attribute descriptor for sysfs ROM entry */
	int rom_attr_enabled;		/* has display of the rom attribute been enabled? */
	struct bin_attribute *res_attr[DEVICE_COUNT_RESOURCE]; /* sysfs file for resources */
	struct bin_attribute *res_attr_wc[DEVICE_COUNT_RESOURCE]; /* sysfs file for WC mapping of resources */
#ifdef CONFIG_PCI_MSI
	struct list_head msi_list;
#endif
	struct pci_vpd *vpd;
#ifdef CONFIG_PCI_ATS
	union {
		struct pci_sriov *sriov;	/* SR-IOV capability related */
		struct pci_dev *physfn;	/* the PF this VF is associated with */
	};
	struct pci_ats	*ats;	/* Address Translation Service */
#endif
};

static inline struct pci_dev *pci_physfn(struct pci_dev *dev)
{
#ifdef CONFIG_PCI_IOV
	if (dev->is_virtfn)
		dev = dev->physfn;
#endif

	return dev;
}

extern struct pci_dev *alloc_pci_dev(void);

#define pci_dev_b(n) list_entry(n, struct pci_dev, bus_list)
#define	to_pci_dev(n) container_of(n, struct pci_dev, dev)
#define for_each_pci_dev(d) while ((d = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, d)) != NULL)

static inline int pci_channel_offline(struct pci_dev *pdev)
{
	return (pdev->error_state != pci_channel_io_normal);
}

static inline struct pci_cap_saved_state *pci_find_saved_cap(
	struct pci_dev *pci_dev, char cap)
{
	struct pci_cap_saved_state *tmp;
	struct hlist_node *pos;

	hlist_for_each_entry(tmp, pos, &pci_dev->saved_cap_space, next) {
		if (tmp->cap.cap_nr == cap)
			return tmp;
	}
	return NULL;
}

static inline void pci_add_saved_cap(struct pci_dev *pci_dev,
	struct pci_cap_saved_state *new_cap)
{
	hlist_add_head(&new_cap->next, &pci_dev->saved_cap_space);
}

/*
 * The first PCI_BRIDGE_RESOURCE_NUM PCI bus resources (those that correspond
 * to P2P or CardBus bridge windows) go in a table.  Additional ones (for
 * buses below host bridges or subtractive decode bridges) go in the list.
 * Use pci_bus_for_each_resource() to iterate through all the resources.
 */

/*
 * PCI_SUBTRACTIVE_DECODE means the bridge forwards the window implicitly
 * and there's no way to program the bridge with the details of the window.
 * This does not apply to ACPI _CRS windows, even with the _DEC subtractive-
 * decode bit set, because they are explicit and can be programmed with _SRS.
 */
#define PCI_SUBTRACTIVE_DECODE	0x1

struct pci_bus_resource {
	struct list_head list;
	struct resource *res;
	unsigned int flags;
};

#define PCI_REGION_FLAG_MASK	0x0fU	/* These bits of resource flags tell us the PCI region flags */

struct pci_bus {
	/* 链表元素node:
	   对于PCI根总线而言，
	   其pci_bus结构通过node成员链接到本节一开始所述的根总线链表中，
	   根总线链表的表头由一个list_head类型的全局变量pci_root_buses所描述。
	   而对于非根pci总线，
	   其pci_bus结构通过node成员链接到其父总线的子总线链表children中(见下面)。
	*/
	struct list_head node;		/* node in list of buses */
	/* parent指针:指向该pci总线的父总线，即pci桥所在的那条总线。 */
	struct pci_bus	*parent;	/* parent bus this bridge is on */
	/* children指针:描述了这条PCI总线的子总线链表的表头。
	   这条PCI总线的所有子总线都通过上述的node链表元素链接成一条子总线链表，
	   而该链表的表头就由父总线的children指针所描述。
	*/
	struct list_head children;	/* list of child buses */
	/* devices链表头:描述了这条PCI总线的逻辑设备链表的表头。
	   除了链接在全局PCI设备链表中之外，
	   每一个PCI逻辑设备也通过其pci_dev结构中的bus_list成员链入其所在PCI总线的局部设备链表中，
	   而这个局部的总线设备链表的表头就由pci_bus结构中的devices成员所描述。
	*/
	struct list_head devices;	/* list of devices on this bus */
	/* 指针self:指向引出这条PCI总线的桥设备的pci_dev结构。 */
	struct pci_dev	*self;		/* bridge device as seen by parent */
	struct list_head slots;		/* list of slots on this bus */
	/* 资源指针数组resource[4]:指向应路由到这条pci总线的地址空间资源，
	   通常是指向对应桥设备的pci_dev结构中的资源数组resource[10-7]。
	*/
	struct resource *resource[PCI_BRIDGE_RESOURCE_NUM];
	struct list_head resources;	/* address space routed to this bus */

	/* 指针ops:指向一个pci_ops结构，表示这条pci总线所使用的配置空间访问函数。 */
	struct pci_ops	*ops;		/* configuration access functions */
	/* 无类型指针sysdata:指向系统特定的扩展数据。 */
	void		*sysdata;	/* hook for sys-specific extension */
	/* 指针procdir:指向该PCI总线在/proc文件系统中对应的目录项。 */
	struct proc_dir_entry *procdir;	/* directory entry in /proc/bus/pci */

	/* number:这条PCI总线的总线编号(bus number)，取值范围0-255。 */
	unsigned char	number;		/* bus number */
	/* primary:表示引出这条PCI总线的"桥设备的主总线"
	   (也即桥设备所在的PCI总线)编号，取值范围0-255。 */
	unsigned char	primary;	/* number of primary bridge */
	/* secondary:表示引出这条PCI总线的桥设备的次总线号，
	   因此secondary成员总是等于number成员的值。取值范围0-255。 */
	unsigned char	secondary;	/* number of secondary bridge */
	/* subordinate:
	   这条PCI总线的下属PCI总线(Subordinate pci bus)的总线编号最大值，
	   它应该等于引出这条PCI总线的桥设备的subordinate值。
	*/
	unsigned char	subordinate;	/* max number of subordinate buses */
	unsigned char	max_bus_speed;	/* enum pci_bus_speed */
	unsigned char	cur_bus_speed;	/* enum pci_bus_speed */

	/* name[48]:这条PCI总线的名字字符串。 */
	char		name[48];

	unsigned short  bridge_ctl;	/* manage NO_ISA/FBB/et al behaviors */
	pci_bus_flags_t bus_flags;	/* Inherited by child busses */
	struct device		*bridge;
	struct device		dev;
	struct bin_attribute	*legacy_io; /* legacy I/O for this bus */
	struct bin_attribute	*legacy_mem; /* legacy mem */
	unsigned int		is_added:1;
};

#define pci_bus_b(n)	list_entry(n, struct pci_bus, node)
#define to_pci_bus(n)	container_of(n, struct pci_bus, dev)

/*
 * Returns true if the pci bus is root (behind host-pci bridge),
 * false otherwise
 */
static inline bool pci_is_root_bus(struct pci_bus *pbus)
{
	return !(pbus->parent);
}

#ifdef CONFIG_PCI_MSI
static inline bool pci_dev_msi_enabled(struct pci_dev *pci_dev)
{
	return pci_dev->msi_enabled || pci_dev->msix_enabled;
}
#else
static inline bool pci_dev_msi_enabled(struct pci_dev *pci_dev) { return false; }
#endif

/*
 * Error values that may be returned by PCI functions.
 */
#define PCIBIOS_SUCCESSFUL		0x00
#define PCIBIOS_FUNC_NOT_SUPPORTED	0x81
#define PCIBIOS_BAD_VENDOR_ID		0x83
#define PCIBIOS_DEVICE_NOT_FOUND	0x86
#define PCIBIOS_BAD_REGISTER_NUMBER	0x87
#define PCIBIOS_SET_FAILED		0x88
#define PCIBIOS_BUFFER_TOO_SMALL	0x89

/* Low-level architecture-dependent routines */

/*
对pci_raw_ops的一层封装
*/
struct pci_ops {
	int (*read)(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 *val);
	int (*write)(struct pci_bus *bus, unsigned int devfn, int where, int size, u32 val);
};

/*
 * ACPI needs to be able to access PCI config space before we've done a
 * PCI bus scan and created pci_bus structures.
 */
extern int raw_pci_read(unsigned int domain, unsigned int bus,
			unsigned int devfn, int reg, int len, u32 *val);
extern int raw_pci_write(unsigned int domain, unsigned int bus,
			unsigned int devfn, int reg, int len, u32 val);

struct pci_bus_region {
	resource_size_t start;
	resource_size_t end;
};

struct pci_dynids {
	spinlock_t lock;            /* protects list, index */
	struct list_head list;      /* for IDs added at runtime */
};

/* ---------------------------------------------------------------- */
/** PCI Error Recovery System (PCI-ERS).  If a PCI device driver provides
 *  a set of callbacks in struct pci_error_handlers, then that device driver
 *  will be notified of PCI bus errors, and will be driven to recovery
 *  when an error occurs.
 */

typedef unsigned int __bitwise pci_ers_result_t;

enum pci_ers_result {
	/* no result/none/not supported in device driver */
	PCI_ERS_RESULT_NONE = (__force pci_ers_result_t) 1,

	/* Device driver can recover without slot reset */
	PCI_ERS_RESULT_CAN_RECOVER = (__force pci_ers_result_t) 2,

	/* Device driver wants slot to be reset. */
	PCI_ERS_RESULT_NEED_RESET = (__force pci_ers_result_t) 3,

	/* Device has completely failed, is unrecoverable */
	PCI_ERS_RESULT_DISCONNECT = (__force pci_ers_result_t) 4,

	/* Device driver is fully recovered and operational */
	PCI_ERS_RESULT_RECOVERED = (__force pci_ers_result_t) 5,
};

/* PCI bus error event callbacks */
struct pci_error_handlers {
	/* PCI bus error detected on this device */
	pci_ers_result_t (*error_detected)(struct pci_dev *dev,
					   enum pci_channel_state error);

	/* MMIO has been re-enabled, but not DMA */
	pci_ers_result_t (*mmio_enabled)(struct pci_dev *dev);

	/* PCI Express link has been reset */
	pci_ers_result_t (*link_reset)(struct pci_dev *dev);

	/* PCI slot has been reset */
	pci_ers_result_t (*slot_reset)(struct pci_dev *dev);

	/* Device driver may resume normal operations */
	void (*resume)(struct pci_dev *dev);
};

/* ---------------------------------------------------------------- */

struct module;
/*
probe函数

如果找到相关设备和我们的pci_device_id结构数组对上号了，
说明我们找到服务对象了，则调用rtl8139_init_one

1 建立net_device结构，让它在内核中代表这个网络设备
  网卡设备既要遵循PCI规范，也要担负起其作为网卡设备的职责，
  于是就分了两块，pci_dev用来负责网卡的PCI规范，
  而这里要说的net_device则是负责网卡的网络设备这个职责

2 开启这个设备(其实是开启了设备的寄存器映射到内存的功能)
  pci_enable_device也是一个内核开发出来的接口，
  主要就是把PCI配置空间的Command域的0位和1位置成了1，
  从而达到了开启设备的目的，因为rtl8139的官方datasheet中，
  说明了这两位的作用就是开启内存映射和I/O映射，如果不开的话，
  那我们以上讨论的把控制寄存器空间映射到内存空间的这一功能就被屏蔽了，
  这对我们是非常不利的，除此之外，pci_enable_device还做了些中断开启工作。

3 获得各项资源
  在硬件加电初始化时，BIOS固件统一检查了所有的PCI设备，
  并统一为他们分配了一个和其他互不冲突的地址，
  让他们的驱动程序可以向这些地址映射他们的寄存器，
  这些地址被BIOS写进了各个设备的配置空间，
  因为这个活动是一个PCI的标准的活动，
  所以自然写到各个设备的配置空间里而不是他们风格各异的控制寄存器空间里。
  当然只有BIOS可以访问配置空间。
  当操作系统初始化时，他为每个PCI设备分配了pci_dev结构，
  并且把BIOS获得的并写到了配置空间中的地址读出来写到了pci_dev中的resource字段中。
  这样以后我们在读这些地址就不需要在访问配置空间了，直接跟pci_dev要就可以了
  每个PCI设备有0-5共6个地址空间，我们通常只使用前两个

4 把得到的地址进行映射
  ioremap是内核提供的用来映射外设寄存器到主存的函数，
  我们要映射的地址已经从pci_dev中读了出来(上一步)，
  这样就水到渠成的成功映射了而不会和其他地址有冲突。
  映射完了有什么效果呢，我举个例子，比如某个网卡有100个寄存器，
  他们都是连在一块的，位置是固定的，假如每个寄存器占4个字节，
  那么一共400个字节的空间被映射到内存成功后，
  ioaddr就是这段地址的开头
  (注意ioaddr是虚拟地址，而mmio_start是物理地址，
  它是BIOS得到的，肯定是物理地址，而保护模式下CPU不认物理地址，只认虚拟地址)，
  ioaddr+0就是第一个寄存器的地址，
  ioaddr+4就是第二个寄存器地址(每个寄存器占4个字节)，
  以此类推，我们就能够在内存中访问到所有的寄存器进而操控他们了。

5 重启网卡设备
  重启网卡设备是初始化网卡设备的一个重要部分，
  它的原理就是向寄存器中写入命令就可以了
  (注意这里写寄存器，而不是配置空间，因为跟PCI没有什么关系)，

6 获得MAC地址，并把它存储到net_device中。
  我们可以看到读的地址是ioaddr+0到ioaddr+5，
  读者查看官方datasheet会发现寄存器地址空间的开头6个字节正好存的是这个网卡设备的MAC地址，
  MAC地址是网络中标识网卡的物理地址，这个地址在今后的收发数据包时会用的上。

7 向net_device中登记一些主要的函数
  由于dev(net_device)代表着设备，
  把这些函数注册完后，rtl8139_open就是用于打开这个设备，
  rtl8139_start_xmit就是当应用程序要通过这个设备往外面发数据时被调用，
  具体的其实这个函数是在网络协议层中调用的，这就涉及到Linux网络协议栈的内容，
  不再我们讨论之列，我们只是负责实现它。
  rtl8139_close用来关掉这个设备。

pci_driver一般由模块定义并且在模块初始化函数中向内核注册
*/
struct pci_driver {
	struct list_head node;
	/* 驱动名称 */
	const char *name;
	/* 驱动支持的设备ID列表 */
	const struct pci_device_id *id_table;	/* must be non-NULL for probe to be called */
	/* 参数dev是系统探测分配的pci_dev结构指针
	   参数id通常是pci驱动中提供的id_table的某一项指针
	*/
	int  (*probe)  (struct pci_dev *dev, const struct pci_device_id *id);	/* New device inserted */
	void (*remove) (struct pci_dev *dev);	/* Device removed (NULL if not a hot-plug capable driver) */
	int  (*suspend) (struct pci_dev *dev, pm_message_t state);	/* Device suspended */
	int  (*suspend_late) (struct pci_dev *dev, pm_message_t state);
	int  (*resume_early) (struct pci_dev *dev);
	int  (*resume) (struct pci_dev *dev);	                /* Device woken up */
	void (*shutdown) (struct pci_dev *dev);
	struct pci_error_handlers *err_handler;
	/* 内嵌的通用设备驱动 */
	struct device_driver	driver;
	struct pci_dynids dynids;
};

#define	to_pci_driver(drv) container_of(drv, struct pci_driver, driver)

/**
 * DEFINE_PCI_DEVICE_TABLE - macro used to describe a pci device table
 * @_table: device table name
 *
 * This macro is used to create a struct pci_device_id array (a device table)
 * in a generic manner.
 */
#define DEFINE_PCI_DEVICE_TABLE(_table) \
	const struct pci_device_id _table[] __devinitconst

/**
 * PCI_DEVICE - macro used to describe a specific pci device
 * @vend: the 16 bit PCI Vendor ID
 * @dev: the 16 bit PCI Device ID
 *
 * This macro is used to create a struct pci_device_id that matches a
 * specific device.  The subvendor and subdevice fields will be set to
 * PCI_ANY_ID.
 */
#define PCI_DEVICE(vend,dev) \
	.vendor = (vend), .device = (dev), \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID

/**
 * PCI_DEVICE_CLASS - macro used to describe a specific pci device class
 * @dev_class: the class, subclass, prog-if triple for this device
 * @dev_class_mask: the class mask for this device
 *
 * This macro is used to create a struct pci_device_id that matches a
 * specific PCI class.  The vendor, device, subvendor, and subdevice
 * fields will be set to PCI_ANY_ID.
 */
#define PCI_DEVICE_CLASS(dev_class,dev_class_mask) \
	.class = (dev_class), .class_mask = (dev_class_mask), \
	.vendor = PCI_ANY_ID, .device = PCI_ANY_ID, \
	.subvendor = PCI_ANY_ID, .subdevice = PCI_ANY_ID

/**
 * PCI_VDEVICE - macro used to describe a specific pci device in short form
 * @vendor: the vendor name
 * @device: the 16 bit PCI Device ID
 *
 * This macro is used to create a struct pci_device_id that matches a
 * specific PCI device.  The subvendor, and subdevice fields will be set
 * to PCI_ANY_ID. The macro allows the next field to follow as the device
 * private data.
 */

#define PCI_VDEVICE(vendor, device)		\
	PCI_VENDOR_ID_##vendor, (device),	\
	PCI_ANY_ID, PCI_ANY_ID, 0, 0

/* these external functions are only available when PCI support is enabled */
#ifdef CONFIG_PCI

extern void pcie_bus_configure_settings(struct pci_bus *bus, u8 smpss);

enum pcie_bus_config_types {
	PCIE_BUS_TUNE_OFF,
	PCIE_BUS_SAFE,
	PCIE_BUS_PERFORMANCE,
	PCIE_BUS_PEER2PEER,
};

extern enum pcie_bus_config_types pcie_bus_config;

extern struct bus_type pci_bus_type;

/* Do NOT directly access these two variables, unless you are arch specific pci
 * code, or pci core code. */
extern struct list_head pci_root_buses;	/* list of all known PCI buses */
/* Some device drivers need know if pci is initiated */
extern int no_pci_devices(void);

void pcibios_fixup_bus(struct pci_bus *);
int __must_check pcibios_enable_device(struct pci_dev *, int mask);
char *pcibios_setup(char *str);

/* Used only when drivers/pci/setup.c is used */
resource_size_t pcibios_align_resource(void *, const struct resource *,
				resource_size_t,
				resource_size_t);
void pcibios_update_irq(struct pci_dev *, int irq);

/* Weak but can be overriden by arch */
void pci_fixup_cardbus(struct pci_bus *);

/* Generic PCI functions used internally */

void pcibios_scan_specific_bus(int busn);
extern struct pci_bus *pci_find_bus(int domain, int busnr);
void pci_bus_add_devices(const struct pci_bus *bus);
struct pci_bus *pci_scan_bus_parented(struct device *parent, int bus,
				      struct pci_ops *ops, void *sysdata);
static inline struct pci_bus * __devinit pci_scan_bus(int bus, struct pci_ops *ops,
					   void *sysdata)
{
	struct pci_bus *root_bus;
	root_bus = pci_scan_bus_parented(NULL, bus, ops, sysdata);
	if (root_bus)
		pci_bus_add_devices(root_bus);
	return root_bus;
}
struct pci_bus *pci_create_bus(struct device *parent, int bus,
			       struct pci_ops *ops, void *sysdata);
struct pci_bus *pci_add_new_bus(struct pci_bus *parent, struct pci_dev *dev,
				int busnr);
void pcie_update_link_speed(struct pci_bus *bus, u16 link_status);
struct pci_slot *pci_create_slot(struct pci_bus *parent, int slot_nr,
				 const char *name,
				 struct hotplug_slot *hotplug);
void pci_destroy_slot(struct pci_slot *slot);
void pci_renumber_slot(struct pci_slot *slot, int slot_nr);
int pci_scan_slot(struct pci_bus *bus, int devfn);
struct pci_dev *pci_scan_single_device(struct pci_bus *bus, int devfn);
void pci_device_add(struct pci_dev *dev, struct pci_bus *bus);
unsigned int pci_scan_child_bus(struct pci_bus *bus);
int __must_check pci_bus_add_device(struct pci_dev *dev);
void pci_read_bridge_bases(struct pci_bus *child);
struct resource *pci_find_parent_resource(const struct pci_dev *dev,
					  struct resource *res);
u8 pci_swizzle_interrupt_pin(struct pci_dev *dev, u8 pin);
int pci_get_interrupt_pin(struct pci_dev *dev, struct pci_dev **bridge);
u8 pci_common_swizzle(struct pci_dev *dev, u8 *pinp);
extern struct pci_dev *pci_dev_get(struct pci_dev *dev);
extern void pci_dev_put(struct pci_dev *dev);
extern void pci_remove_bus(struct pci_bus *b);
extern void pci_remove_bus_device(struct pci_dev *dev);
extern void pci_stop_bus_device(struct pci_dev *dev);
void pci_setup_cardbus(struct pci_bus *bus);
extern void pci_sort_breadthfirst(void);
#define dev_is_pci(d) ((d)->bus == &pci_bus_type)
#define dev_is_pf(d) ((dev_is_pci(d) ? to_pci_dev(d)->is_physfn : false))
#define dev_num_vf(d) ((dev_is_pci(d) ? pci_num_vf(to_pci_dev(d)) : 0))

/* Generic PCI functions exported to card drivers */

enum pci_lost_interrupt_reason {
	PCI_LOST_IRQ_NO_INFORMATION = 0,
	PCI_LOST_IRQ_DISABLE_MSI,
	PCI_LOST_IRQ_DISABLE_MSIX,
	PCI_LOST_IRQ_DISABLE_ACPI,
};
enum pci_lost_interrupt_reason pci_lost_interrupt(struct pci_dev *dev);
int pci_find_capability(struct pci_dev *dev, int cap);
int pci_find_next_capability(struct pci_dev *dev, u8 pos, int cap);
int pci_find_ext_capability(struct pci_dev *dev, int cap);
int pci_bus_find_ext_capability(struct pci_bus *bus, unsigned int devfn,
				int cap);
int pci_find_ht_capability(struct pci_dev *dev, int ht_cap);
int pci_find_next_ht_capability(struct pci_dev *dev, int pos, int ht_cap);
struct pci_bus *pci_find_next_bus(const struct pci_bus *from);

struct pci_dev *pci_get_device(unsigned int vendor, unsigned int device,
				struct pci_dev *from);
struct pci_dev *pci_get_subsys(unsigned int vendor, unsigned int device,
				unsigned int ss_vendor, unsigned int ss_device,
				struct pci_dev *from);
struct pci_dev *pci_get_slot(struct pci_bus *bus, unsigned int devfn);
struct pci_dev *pci_get_domain_bus_and_slot(int domain, unsigned int bus,
					    unsigned int devfn);
static inline struct pci_dev *pci_get_bus_and_slot(unsigned int bus,
						   unsigned int devfn)
{
	return pci_get_domain_bus_and_slot(0, bus, devfn);
}
struct pci_dev *pci_get_class(unsigned int class, struct pci_dev *from);
int pci_dev_present(const struct pci_device_id *ids);

/*
这些函数在drivers/pci/access.c中由宏定义

最后都是调用该总线内通过指针提供的底层读写函数
函数执行成功返回0，并会将值保存在参数@val的指针内
执行失败会返回负的错误码
*/
int pci_bus_read_config_byte(struct pci_bus *bus, unsigned int devfn,
			     int where, u8 *val);
int pci_bus_read_config_word(struct pci_bus *bus, unsigned int devfn,
			     int where, u16 *val);
int pci_bus_read_config_dword(struct pci_bus *bus, unsigned int devfn,
			      int where, u32 *val);
int pci_bus_write_config_byte(struct pci_bus *bus, unsigned int devfn,
			      int where, u8 val);
int pci_bus_write_config_word(struct pci_bus *bus, unsigned int devfn,
			      int where, u16 val);
int pci_bus_write_config_dword(struct pci_bus *bus, unsigned int devfn,
			       int where, u32 val);
struct pci_ops *pci_bus_set_ops(struct pci_bus *bus, struct pci_ops *ops);

static inline int pci_read_config_byte(struct pci_dev *dev, int where, u8 *val)
{
	return pci_bus_read_config_byte(dev->bus, dev->devfn, where, val);
}
static inline int pci_read_config_word(struct pci_dev *dev, int where, u16 *val)
{
	return pci_bus_read_config_word(dev->bus, dev->devfn, where, val);
}
static inline int pci_read_config_dword(struct pci_dev *dev, int where,
					u32 *val)
{
	return pci_bus_read_config_dword(dev->bus, dev->devfn, where, val);
}
static inline int pci_write_config_byte(struct pci_dev *dev, int where, u8 val)
{
	return pci_bus_write_config_byte(dev->bus, dev->devfn, where, val);
}
static inline int pci_write_config_word(struct pci_dev *dev, int where, u16 val)
{
	return pci_bus_write_config_word(dev->bus, dev->devfn, where, val);
}
static inline int pci_write_config_dword(struct pci_dev *dev, int where,
					 u32 val)
{
	return pci_bus_write_config_dword(dev->bus, dev->devfn, where, val);
}

int __must_check pci_enable_device(struct pci_dev *dev);
int __must_check pci_enable_device_io(struct pci_dev *dev);
int __must_check pci_enable_device_mem(struct pci_dev *dev);
int __must_check pci_reenable_device(struct pci_dev *);
int __must_check pcim_enable_device(struct pci_dev *pdev);
void pcim_pin_device(struct pci_dev *pdev);

static inline int pci_is_enabled(struct pci_dev *pdev)
{
	return (atomic_read(&pdev->enable_cnt) > 0);
}

static inline int pci_is_managed(struct pci_dev *pdev)
{
	return pdev->is_managed;
}

void pci_disable_device(struct pci_dev *dev);
void pci_set_master(struct pci_dev *dev);
void pci_clear_master(struct pci_dev *dev);
int pci_set_pcie_reset_state(struct pci_dev *dev, enum pcie_reset_state state);
int pci_set_cacheline_size(struct pci_dev *dev);
#define HAVE_PCI_SET_MWI
int __must_check pci_set_mwi(struct pci_dev *dev);
int pci_try_set_mwi(struct pci_dev *dev);
void pci_clear_mwi(struct pci_dev *dev);
void pci_intx(struct pci_dev *dev, int enable);
void pci_msi_off(struct pci_dev *dev);
int pci_set_dma_max_seg_size(struct pci_dev *dev, unsigned int size);
int pci_set_dma_seg_boundary(struct pci_dev *dev, unsigned long mask);
int pcix_get_max_mmrbc(struct pci_dev *dev);
int pcix_get_mmrbc(struct pci_dev *dev);
int pcix_set_mmrbc(struct pci_dev *dev, int mmrbc);
int pcie_get_readrq(struct pci_dev *dev);
int pcie_set_readrq(struct pci_dev *dev, int rq);
int pcie_get_mps(struct pci_dev *dev);
int pcie_set_mps(struct pci_dev *dev, int mps);
int __pci_reset_function(struct pci_dev *dev);
int pci_reset_function(struct pci_dev *dev);
void pci_update_resource(struct pci_dev *dev, int resno);
int __must_check pci_assign_resource(struct pci_dev *dev, int i);
int __must_check pci_reassign_resource(struct pci_dev *dev, int i, resource_size_t add_size, resource_size_t align);
int pci_select_bars(struct pci_dev *dev, unsigned long flags);

/* ROM control related routines */
int pci_enable_rom(struct pci_dev *pdev);
void pci_disable_rom(struct pci_dev *pdev);
void __iomem __must_check *pci_map_rom(struct pci_dev *pdev, size_t *size);
void pci_unmap_rom(struct pci_dev *pdev, void __iomem *rom);
size_t pci_get_rom_size(struct pci_dev *pdev, void __iomem *rom, size_t size);

/* Power management related routines */
int pci_save_state(struct pci_dev *dev);
void pci_restore_state(struct pci_dev *dev);
struct pci_saved_state *pci_store_saved_state(struct pci_dev *dev);
int pci_load_saved_state(struct pci_dev *dev, struct pci_saved_state *state);
int pci_load_and_free_saved_state(struct pci_dev *dev,
				  struct pci_saved_state **state);
int __pci_complete_power_transition(struct pci_dev *dev, pci_power_t state);
int pci_set_power_state(struct pci_dev *dev, pci_power_t state);
pci_power_t pci_choose_state(struct pci_dev *dev, pm_message_t state);
bool pci_pme_capable(struct pci_dev *dev, pci_power_t state);
void pci_pme_active(struct pci_dev *dev, bool enable);
int __pci_enable_wake(struct pci_dev *dev, pci_power_t state,
		      bool runtime, bool enable);
int pci_wake_from_d3(struct pci_dev *dev, bool enable);
pci_power_t pci_target_state(struct pci_dev *dev);
int pci_prepare_to_sleep(struct pci_dev *dev);
int pci_back_from_sleep(struct pci_dev *dev);
bool pci_dev_run_wake(struct pci_dev *dev);
bool pci_check_pme_status(struct pci_dev *dev);
void pci_pme_wakeup_bus(struct pci_bus *bus);

static inline int pci_enable_wake(struct pci_dev *dev, pci_power_t state,
				  bool enable)
{
	return __pci_enable_wake(dev, state, false, enable);
}

#define PCI_EXP_IDO_REQUEST	(1<<0)
#define PCI_EXP_IDO_COMPLETION	(1<<1)
void pci_enable_ido(struct pci_dev *dev, unsigned long type);
void pci_disable_ido(struct pci_dev *dev, unsigned long type);

enum pci_obff_signal_type {
	PCI_EXP_OBFF_SIGNAL_L0 = 0,
	PCI_EXP_OBFF_SIGNAL_ALWAYS = 1,
};
int pci_enable_obff(struct pci_dev *dev, enum pci_obff_signal_type);
void pci_disable_obff(struct pci_dev *dev);

bool pci_ltr_supported(struct pci_dev *dev);
int pci_enable_ltr(struct pci_dev *dev);
void pci_disable_ltr(struct pci_dev *dev);
int pci_set_ltr(struct pci_dev *dev, int snoop_lat_ns, int nosnoop_lat_ns);

/* For use by arch with custom probe code */
void set_pcie_port_type(struct pci_dev *pdev);
void set_pcie_hotplug_bridge(struct pci_dev *pdev);

/* Functions for PCI Hotplug drivers to use */
int pci_bus_find_capability(struct pci_bus *bus, unsigned int devfn, int cap);
#ifdef CONFIG_HOTPLUG
unsigned int pci_rescan_bus(struct pci_bus *bus);
#endif

/* Vital product data routines */
ssize_t pci_read_vpd(struct pci_dev *dev, loff_t pos, size_t count, void *buf);
ssize_t pci_write_vpd(struct pci_dev *dev, loff_t pos, size_t count, const void *buf);
int pci_vpd_truncate(struct pci_dev *dev, size_t size);

/* Helper functions for low-level code (drivers/pci/setup-[bus,res].c) */
void pci_bus_assign_resources(const struct pci_bus *bus);
void pci_bus_size_bridges(struct pci_bus *bus);
int pci_claim_resource(struct pci_dev *, int);
void pci_assign_unassigned_resources(void);
void pci_assign_unassigned_bridge_resources(struct pci_dev *bridge);
void pdev_enable_device(struct pci_dev *);
void pdev_sort_resources(struct pci_dev *, struct resource_list *);
int pci_enable_resources(struct pci_dev *, int mask);
void pci_fixup_irqs(u8 (*)(struct pci_dev *, u8 *),
		    int (*)(const struct pci_dev *, u8, u8));
#define HAVE_PCI_REQ_REGIONS	2
int __must_check pci_request_regions(struct pci_dev *, const char *);
int __must_check pci_request_regions_exclusive(struct pci_dev *, const char *);
void pci_release_regions(struct pci_dev *);
int __must_check pci_request_region(struct pci_dev *, int, const char *);
int __must_check pci_request_region_exclusive(struct pci_dev *, int, const char *);
void pci_release_region(struct pci_dev *, int);
int pci_request_selected_regions(struct pci_dev *, int, const char *);
int pci_request_selected_regions_exclusive(struct pci_dev *, int, const char *);
void pci_release_selected_regions(struct pci_dev *, int);

/* drivers/pci/bus.c */
void pci_bus_add_resource(struct pci_bus *bus, struct resource *res, unsigned int flags);
struct resource *pci_bus_resource_n(const struct pci_bus *bus, int n);
void pci_bus_remove_resources(struct pci_bus *bus);

#define pci_bus_for_each_resource(bus, res, i)				\
	for (i = 0;							\
	    (res = pci_bus_resource_n(bus, i)) || i < PCI_BRIDGE_RESOURCE_NUM; \
	     i++)

int __must_check pci_bus_alloc_resource(struct pci_bus *bus,
			struct resource *res, resource_size_t size,
			resource_size_t align, resource_size_t min,
			unsigned int type_mask,
			resource_size_t (*alignf)(void *,
						  const struct resource *,
						  resource_size_t,
						  resource_size_t),
			void *alignf_data);
void pci_enable_bridges(struct pci_bus *bus);

/* Proper probing supporting hot-pluggable devices */
int __must_check __pci_register_driver(struct pci_driver *, struct module *,
				       const char *mod_name);

/*
 * pci_register_driver must be a macro so that KBUILD_MODNAME can be expanded
 */
/*
1 把参数@driver在内核中进行注册，内核中有一个pci设备的大链表，把参数挂载到这个大链表中

2 查看总线上所有PCI设备(网卡设备属于PCI设备的一种)的配置空间，
  如果发现标识信息与参数@driver中的id_table相同
  那么就说明这个驱动程序就是用来驱动这个设备的，
  于是调用参数@driver中的probe函数，
  这个函数在驱动程序中定义，用来初始化整个设备和做一些准备工作
  这里需要注意一下pci_device_id是内核定义的用来辨别不同PCI设备的一个结构，
  例如在我们这里0x10ec代表的是Realtek公司，
  我们扫描PCI设备配置空间如果发现有Realtek公司制造的设备时，两者就对上了。
  当然对上了公司号后还得看其他的设备号什么的，都对上了才说明这个驱动是可以为这个设备服务的

3 把这个rtl8139_pci_driver结构挂在这个设备的数据结构(pci_dev)上，
  表示这个设备从此就有了自己的驱动了。而驱动也找到了它服务的对象了
*/
#define pci_register_driver(driver)		\
	__pci_register_driver(driver, THIS_MODULE, KBUILD_MODNAME)

void pci_unregister_driver(struct pci_driver *dev);
void pci_remove_behind_bridge(struct pci_dev *dev);
struct pci_driver *pci_dev_driver(const struct pci_dev *dev);
int pci_add_dynid(struct pci_driver *drv,
		  unsigned int vendor, unsigned int device,
		  unsigned int subvendor, unsigned int subdevice,
		  unsigned int class, unsigned int class_mask,
		  unsigned long driver_data);
const struct pci_device_id *pci_match_id(const struct pci_device_id *ids,
					 struct pci_dev *dev);
int pci_scan_bridge(struct pci_bus *bus, struct pci_dev *dev, int max,
		    int pass);

void pci_walk_bus(struct pci_bus *top, int (*cb)(struct pci_dev *, void *),
		  void *userdata);
int pci_cfg_space_size_ext(struct pci_dev *dev);
int pci_cfg_space_size(struct pci_dev *dev);
unsigned char pci_bus_max_busnr(struct pci_bus *bus);
void pci_setup_bridge(struct pci_bus *bus);

#define PCI_VGA_STATE_CHANGE_BRIDGE (1 << 0)
#define PCI_VGA_STATE_CHANGE_DECODES (1 << 1)

int pci_set_vga_state(struct pci_dev *pdev, bool decode,
		      unsigned int command_bits, u32 flags);
/* kmem_cache style wrapper around pci_alloc_consistent() */

#include <linux/pci-dma.h>
#include <linux/dmapool.h>

#define	pci_pool dma_pool
#define pci_pool_create(name, pdev, size, align, allocation) \
		dma_pool_create(name, &pdev->dev, size, align, allocation)
#define	pci_pool_destroy(pool) dma_pool_destroy(pool)
#define	pci_pool_alloc(pool, flags, handle) dma_pool_alloc(pool, flags, handle)
#define	pci_pool_free(pool, vaddr, addr) dma_pool_free(pool, vaddr, addr)

enum pci_dma_burst_strategy {
	PCI_DMA_BURST_INFINITY,	/* make bursts as large as possible,
				   strategy_parameter is N/A */
	PCI_DMA_BURST_BOUNDARY, /* disconnect at every strategy_parameter
				   byte boundaries */
	PCI_DMA_BURST_MULTIPLE, /* disconnect at some multiple of
				   strategy_parameter byte boundaries */
};

struct msix_entry {
	u32	vector;	/* kernel uses to write allocated vector */
	u16	entry;	/* driver uses to specify entry, OS writes */
};


#ifndef CONFIG_PCI_MSI
static inline int pci_enable_msi_block(struct pci_dev *dev, unsigned int nvec)
{
	return -1;
}

static inline void pci_msi_shutdown(struct pci_dev *dev)
{ }
static inline void pci_disable_msi(struct pci_dev *dev)
{ }

static inline int pci_msix_table_size(struct pci_dev *dev)
{
	return 0;
}
static inline int pci_enable_msix(struct pci_dev *dev,
				  struct msix_entry *entries, int nvec)
{
	return -1;
}

static inline void pci_msix_shutdown(struct pci_dev *dev)
{ }
static inline void pci_disable_msix(struct pci_dev *dev)
{ }

static inline void msi_remove_pci_irq_vectors(struct pci_dev *dev)
{ }

static inline void pci_restore_msi_state(struct pci_dev *dev)
{ }
static inline int pci_msi_enabled(void)
{
	return 0;
}
#else
extern int pci_enable_msi_block(struct pci_dev *dev, unsigned int nvec);
extern void pci_msi_shutdown(struct pci_dev *dev);
extern void pci_disable_msi(struct pci_dev *dev);
extern int pci_msix_table_size(struct pci_dev *dev);
extern int pci_enable_msix(struct pci_dev *dev,
	struct msix_entry *entries, int nvec);
extern void pci_msix_shutdown(struct pci_dev *dev);
extern void pci_disable_msix(struct pci_dev *dev);
extern void msi_remove_pci_irq_vectors(struct pci_dev *dev);
extern void pci_restore_msi_state(struct pci_dev *dev);
extern int pci_msi_enabled(void);
#endif

#ifdef CONFIG_PCIEPORTBUS
extern bool pcie_ports_disabled;
extern bool pcie_ports_auto;
#else
#define pcie_ports_disabled	true
#define pcie_ports_auto		false
#endif

#ifndef CONFIG_PCIEASPM
static inline int pcie_aspm_enabled(void) { return 0; }
static inline bool pcie_aspm_support_enabled(void) { return false; }
#else
extern int pcie_aspm_enabled(void);
extern bool pcie_aspm_support_enabled(void);
#endif

#ifdef CONFIG_PCIEAER
void pci_no_aer(void);
bool pci_aer_available(void);
#else
static inline void pci_no_aer(void) { }
static inline bool pci_aer_available(void) { return false; }
#endif

#ifndef CONFIG_PCIE_ECRC
static inline void pcie_set_ecrc_checking(struct pci_dev *dev)
{
	return;
}
static inline void pcie_ecrc_get_policy(char *str) {};
#else
extern void pcie_set_ecrc_checking(struct pci_dev *dev);
extern void pcie_ecrc_get_policy(char *str);
#endif

#define pci_enable_msi(pdev)	pci_enable_msi_block(pdev, 1)

#ifdef CONFIG_HT_IRQ
/* The functions a driver should call */
int  ht_create_irq(struct pci_dev *dev, int idx);
void ht_destroy_irq(unsigned int irq);
#endif /* CONFIG_HT_IRQ */

extern void pci_block_user_cfg_access(struct pci_dev *dev);
extern void pci_unblock_user_cfg_access(struct pci_dev *dev);

/*
 * PCI domain support.  Sometimes called PCI segment (eg by ACPI),
 * a PCI domain is defined to be a set of PCI busses which share
 * configuration space.
 */
#ifdef CONFIG_PCI_DOMAINS
extern int pci_domains_supported;
#else
enum { pci_domains_supported = 0 };
static inline int pci_domain_nr(struct pci_bus *bus)
{
	return 0;
}

static inline int pci_proc_domain(struct pci_bus *bus)
{
	return 0;
}
#endif /* CONFIG_PCI_DOMAINS */

/* some architectures require additional setup to direct VGA traffic */
typedef int (*arch_set_vga_state_t)(struct pci_dev *pdev, bool decode,
		      unsigned int command_bits, u32 flags);
extern void pci_register_set_vga_state(arch_set_vga_state_t func);

#else /* CONFIG_PCI is not enabled */

/*
 *  If the system does not have PCI, clearly these return errors.  Define
 *  these as simple inline functions to avoid hair in drivers.
 */

#define _PCI_NOP(o, s, t) \
	static inline int pci_##o##_config_##s(struct pci_dev *dev, \
						int where, t val) \
		{ return PCIBIOS_FUNC_NOT_SUPPORTED; }

#define _PCI_NOP_ALL(o, x)	_PCI_NOP(o, byte, u8 x) \
				_PCI_NOP(o, word, u16 x) \
				_PCI_NOP(o, dword, u32 x)
_PCI_NOP_ALL(read, *)
_PCI_NOP_ALL(write,)

static inline struct pci_dev *pci_get_device(unsigned int vendor,
					     unsigned int device,
					     struct pci_dev *from)
{
	return NULL;
}

static inline struct pci_dev *pci_get_subsys(unsigned int vendor,
					     unsigned int device,
					     unsigned int ss_vendor,
					     unsigned int ss_device,
					     struct pci_dev *from)
{
	return NULL;
}

static inline struct pci_dev *pci_get_class(unsigned int class,
					    struct pci_dev *from)
{
	return NULL;
}

#define pci_dev_present(ids)	(0)
#define no_pci_devices()	(1)
#define pci_dev_put(dev)	do { } while (0)

static inline void pci_set_master(struct pci_dev *dev)
{ }

static inline int pci_enable_device(struct pci_dev *dev)
{
	return -EIO;
}

static inline void pci_disable_device(struct pci_dev *dev)
{ }

static inline int pci_set_dma_mask(struct pci_dev *dev, u64 mask)
{
	return -EIO;
}

static inline int pci_set_consistent_dma_mask(struct pci_dev *dev, u64 mask)
{
	return -EIO;
}

static inline int pci_set_dma_max_seg_size(struct pci_dev *dev,
					unsigned int size)
{
	return -EIO;
}

static inline int pci_set_dma_seg_boundary(struct pci_dev *dev,
					unsigned long mask)
{
	return -EIO;
}

static inline int pci_assign_resource(struct pci_dev *dev, int i)
{
	return -EBUSY;
}

static inline int __pci_register_driver(struct pci_driver *drv,
					struct module *owner)
{
	return 0;
}

static inline int pci_register_driver(struct pci_driver *drv)
{
	return 0;
}

static inline void pci_unregister_driver(struct pci_driver *drv)
{ }

static inline int pci_find_capability(struct pci_dev *dev, int cap)
{
	return 0;
}

static inline int pci_find_next_capability(struct pci_dev *dev, u8 post,
					   int cap)
{
	return 0;
}

static inline int pci_find_ext_capability(struct pci_dev *dev, int cap)
{
	return 0;
}

/* Power management related routines */
static inline int pci_save_state(struct pci_dev *dev)
{
	return 0;
}

static inline void pci_restore_state(struct pci_dev *dev)
{ }

static inline int pci_set_power_state(struct pci_dev *dev, pci_power_t state)
{
	return 0;
}

static inline int pci_wake_from_d3(struct pci_dev *dev, bool enable)
{
	return 0;
}

static inline pci_power_t pci_choose_state(struct pci_dev *dev,
					   pm_message_t state)
{
	return PCI_D0;
}

static inline int pci_enable_wake(struct pci_dev *dev, pci_power_t state,
				  int enable)
{
	return 0;
}

static inline void pci_enable_ido(struct pci_dev *dev, unsigned long type)
{
}

static inline void pci_disable_ido(struct pci_dev *dev, unsigned long type)
{
}

static inline int pci_enable_obff(struct pci_dev *dev, unsigned long type)
{
	return 0;
}

static inline void pci_disable_obff(struct pci_dev *dev)
{
}

static inline int pci_request_regions(struct pci_dev *dev, const char *res_name)
{
	return -EIO;
}

static inline void pci_release_regions(struct pci_dev *dev)
{ }

#define pci_dma_burst_advice(pdev, strat, strategy_parameter) do { } while (0)

static inline void pci_block_user_cfg_access(struct pci_dev *dev)
{ }

static inline void pci_unblock_user_cfg_access(struct pci_dev *dev)
{ }

static inline struct pci_bus *pci_find_next_bus(const struct pci_bus *from)
{ return NULL; }

static inline struct pci_dev *pci_get_slot(struct pci_bus *bus,
						unsigned int devfn)
{ return NULL; }

static inline struct pci_dev *pci_get_bus_and_slot(unsigned int bus,
						unsigned int devfn)
{ return NULL; }

static inline int pci_domain_nr(struct pci_bus *bus)
{ return 0; }

#define dev_is_pci(d) (false)
#define dev_is_pf(d) (false)
#define dev_num_vf(d) (0)
#endif /* CONFIG_PCI */

/* Include architecture-dependent settings and functions */

#include <asm/pci.h>

#ifndef PCIBIOS_MAX_MEM_32
#define PCIBIOS_MAX_MEM_32 (-1)
#endif

/* these helpers provide future and backwards compatibility
 * for accessing popular PCI BAR info */
/*
把参数1传给了bar就是使用内存映射的地址空间
*/
#define pci_resource_start(dev, bar)	((dev)->resource[(bar)].start)
#define pci_resource_end(dev, bar)	((dev)->resource[(bar)].end)
#define pci_resource_flags(dev, bar)	((dev)->resource[(bar)].flags)
#define pci_resource_len(dev,bar) \
	((pci_resource_start((dev), (bar)) == 0 &&	\
	  pci_resource_end((dev), (bar)) ==		\
	  pci_resource_start((dev), (bar))) ? 0 :	\
							\
	 (pci_resource_end((dev), (bar)) -		\
	  pci_resource_start((dev), (bar)) + 1))

/* Similar to the helpers above, these manipulate per-pci_dev
 * driver-specific data.  They are really just a wrapper around
 * the generic device structure functions of these calls.
 */
static inline void *pci_get_drvdata(struct pci_dev *pdev)
{
	return dev_get_drvdata(&pdev->dev);
}

static inline void pci_set_drvdata(struct pci_dev *pdev, void *data)
{
	dev_set_drvdata(&pdev->dev, data);
}

/* If you want to know what to call your pci_dev, ask this function.
 * Again, it's a wrapper around the generic device.
 */
static inline const char *pci_name(const struct pci_dev *pdev)
{
	return dev_name(&pdev->dev);
}


/* Some archs don't want to expose struct resource to userland as-is
 * in sysfs and /proc
 */
#ifndef HAVE_ARCH_PCI_RESOURCE_TO_USER
static inline void pci_resource_to_user(const struct pci_dev *dev, int bar,
		const struct resource *rsrc, resource_size_t *start,
		resource_size_t *end)
{
	*start = rsrc->start;
	*end = rsrc->end;
}
#endif /* HAVE_ARCH_PCI_RESOURCE_TO_USER */


/*
 *  The world is not perfect and supplies us with broken PCI devices.
 *  For at least a part of these bugs we need a work-around, so both
 *  generic (drivers/pci/quirks.c) and per-architecture code can define
 *  fixup hooks to be called for particular buggy devices.
 */

/*
这个数据结构表示，对于厂商vendor提供的设备device，需要在何时执行@hook函数
*/
struct pci_fixup {
	u16 vendor, device;	/* You can use PCI_ANY_ID here of course */
	void (*hook)(struct pci_dev *dev);
};

enum pci_fixup_pass {
	pci_fixup_early,	/* Before probing BARs */
	pci_fixup_header,	/* After reading configuration header */
	pci_fixup_final,	/* Final phase of device fixups */
	pci_fixup_enable,	/* pci_enable_device() time */
	pci_fixup_resume,	/* pci_device_resume() */
	pci_fixup_suspend,	/* pci_device_suspend */
	pci_fixup_resume_early, /* pci_device_resume_early() */
};

/* Anonymous variables would be nice... */
#define DECLARE_PCI_FIXUP_SECTION(section, name, vendor, device, hook)	\
	static const struct pci_fixup __pci_fixup_##name __used		\
	__attribute__((__section__(#section))) = { vendor, device, hook };
#define DECLARE_PCI_FIXUP_EARLY(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_early,			\
			vendor##device##hook, vendor, device, hook)
#define DECLARE_PCI_FIXUP_HEADER(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_header,			\
			vendor##device##hook, vendor, device, hook)
#define DECLARE_PCI_FIXUP_FINAL(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_final,			\
			vendor##device##hook, vendor, device, hook)
#define DECLARE_PCI_FIXUP_ENABLE(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_enable,			\
			vendor##device##hook, vendor, device, hook)
#define DECLARE_PCI_FIXUP_RESUME(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_resume,			\
			resume##vendor##device##hook, vendor, device, hook)
#define DECLARE_PCI_FIXUP_RESUME_EARLY(vendor, device, hook)		\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_resume_early,		\
			resume_early##vendor##device##hook, vendor, device, hook)
#define DECLARE_PCI_FIXUP_SUSPEND(vendor, device, hook)			\
	DECLARE_PCI_FIXUP_SECTION(.pci_fixup_suspend,			\
			suspend##vendor##device##hook, vendor, device, hook)

#ifdef CONFIG_PCI_QUIRKS
void pci_fixup_device(enum pci_fixup_pass pass, struct pci_dev *dev);
#else
static inline void pci_fixup_device(enum pci_fixup_pass pass,
				    struct pci_dev *dev) {}
#endif

void __iomem *pcim_iomap(struct pci_dev *pdev, int bar, unsigned long maxlen);
void pcim_iounmap(struct pci_dev *pdev, void __iomem *addr);
void __iomem * const *pcim_iomap_table(struct pci_dev *pdev);
int pcim_iomap_regions(struct pci_dev *pdev, u16 mask, const char *name);
int pcim_iomap_regions_request_all(struct pci_dev *pdev, u16 mask,
				   const char *name);
void pcim_iounmap_regions(struct pci_dev *pdev, u16 mask);

extern int pci_pci_problems;
#define PCIPCI_FAIL		1	/* No PCI PCI DMA */
#define PCIPCI_TRITON		2
#define PCIPCI_NATOMA		4
#define PCIPCI_VIAETBF		8
#define PCIPCI_VSFX		16
#define PCIPCI_ALIMAGIK		32	/* Need low latency setting */
#define PCIAGP_FAIL		64	/* No PCI to AGP DMA */

extern unsigned long pci_cardbus_io_size;
extern unsigned long pci_cardbus_mem_size;
extern u8 __devinitdata pci_dfl_cache_line_size;
extern u8 pci_cache_line_size;

extern unsigned long pci_hotplug_io_size;
extern unsigned long pci_hotplug_mem_size;

int pcibios_add_platform_entries(struct pci_dev *dev);
void pcibios_disable_device(struct pci_dev *dev);
int pcibios_set_pcie_reset_state(struct pci_dev *dev,
				 enum pcie_reset_state state);

#ifdef CONFIG_PCI_MMCONFIG
extern void __init pci_mmcfg_early_init(void);
extern void __init pci_mmcfg_late_init(void);
#else
static inline void pci_mmcfg_early_init(void) { }
static inline void pci_mmcfg_late_init(void) { }
#endif

int pci_ext_cfg_avail(struct pci_dev *dev);

void __iomem *pci_ioremap_bar(struct pci_dev *pdev, int bar);

#ifdef CONFIG_PCI_IOV
extern int pci_enable_sriov(struct pci_dev *dev, int nr_virtfn);
extern void pci_disable_sriov(struct pci_dev *dev);
extern irqreturn_t pci_sriov_migration(struct pci_dev *dev);
extern int pci_num_vf(struct pci_dev *dev);
#else
static inline int pci_enable_sriov(struct pci_dev *dev, int nr_virtfn)
{
	return -ENODEV;
}
static inline void pci_disable_sriov(struct pci_dev *dev)
{
}
static inline irqreturn_t pci_sriov_migration(struct pci_dev *dev)
{
	return IRQ_NONE;
}
static inline int pci_num_vf(struct pci_dev *dev)
{
	return 0;
}
#endif

#if defined(CONFIG_HOTPLUG_PCI) || defined(CONFIG_HOTPLUG_PCI_MODULE)
extern void pci_hp_create_module_link(struct pci_slot *pci_slot);
extern void pci_hp_remove_module_link(struct pci_slot *pci_slot);
#endif

/**
 * pci_pcie_cap - get the saved PCIe capability offset
 * @dev: PCI device
 *
 * PCIe capability offset is calculated at PCI device initialization
 * time and saved in the data structure. This function returns saved
 * PCIe capability offset. Using this instead of pci_find_capability()
 * reduces unnecessary search in the PCI configuration space. If you
 * need to calculate PCIe capability offset from raw device for some
 * reasons, please use pci_find_capability() instead.
 */
static inline int pci_pcie_cap(struct pci_dev *dev)
{
	return dev->pcie_cap;
}

/**
 * pci_is_pcie - check if the PCI device is PCI Express capable
 * @dev: PCI device
 *
 * Retrun true if the PCI device is PCI Express capable, false otherwise.
 */
static inline bool pci_is_pcie(struct pci_dev *dev)
{
	return !!pci_pcie_cap(dev);
}

void pci_request_acs(void);


#define PCI_VPD_LRDT			0x80	/* Large Resource Data Type */
#define PCI_VPD_LRDT_ID(x)		(x | PCI_VPD_LRDT)

/* Large Resource Data Type Tag Item Names */
#define PCI_VPD_LTIN_ID_STRING		0x02	/* Identifier String */
#define PCI_VPD_LTIN_RO_DATA		0x10	/* Read-Only Data */
#define PCI_VPD_LTIN_RW_DATA		0x11	/* Read-Write Data */

#define PCI_VPD_LRDT_ID_STRING		PCI_VPD_LRDT_ID(PCI_VPD_LTIN_ID_STRING)
#define PCI_VPD_LRDT_RO_DATA		PCI_VPD_LRDT_ID(PCI_VPD_LTIN_RO_DATA)
#define PCI_VPD_LRDT_RW_DATA		PCI_VPD_LRDT_ID(PCI_VPD_LTIN_RW_DATA)

/* Small Resource Data Type Tag Item Names */
#define PCI_VPD_STIN_END		0x78	/* End */

#define PCI_VPD_SRDT_END		PCI_VPD_STIN_END

#define PCI_VPD_SRDT_TIN_MASK		0x78
#define PCI_VPD_SRDT_LEN_MASK		0x07

#define PCI_VPD_LRDT_TAG_SIZE		3
#define PCI_VPD_SRDT_TAG_SIZE		1

#define PCI_VPD_INFO_FLD_HDR_SIZE	3

#define PCI_VPD_RO_KEYWORD_PARTNO	"PN"
#define PCI_VPD_RO_KEYWORD_MFR_ID	"MN"
#define PCI_VPD_RO_KEYWORD_VENDOR0	"V0"
#define PCI_VPD_RO_KEYWORD_CHKSUM	"RV"

/**
 * pci_vpd_lrdt_size - Extracts the Large Resource Data Type length
 * @lrdt: Pointer to the beginning of the Large Resource Data Type tag
 *
 * Returns the extracted Large Resource Data Type length.
 */
static inline u16 pci_vpd_lrdt_size(const u8 *lrdt)
{
	return (u16)lrdt[1] + ((u16)lrdt[2] << 8);
}

/**
 * pci_vpd_srdt_size - Extracts the Small Resource Data Type length
 * @lrdt: Pointer to the beginning of the Small Resource Data Type tag
 *
 * Returns the extracted Small Resource Data Type length.
 */
static inline u8 pci_vpd_srdt_size(const u8 *srdt)
{
	return (*srdt) & PCI_VPD_SRDT_LEN_MASK;
}

/**
 * pci_vpd_info_field_size - Extracts the information field length
 * @lrdt: Pointer to the beginning of an information field header
 *
 * Returns the extracted information field length.
 */
static inline u8 pci_vpd_info_field_size(const u8 *info_field)
{
	return info_field[2];
}

/**
 * pci_vpd_find_tag - Locates the Resource Data Type tag provided
 * @buf: Pointer to buffered vpd data
 * @off: The offset into the buffer at which to begin the search
 * @len: The length of the vpd buffer
 * @rdt: The Resource Data Type to search for
 *
 * Returns the index where the Resource Data Type was found or
 * -ENOENT otherwise.
 */
int pci_vpd_find_tag(const u8 *buf, unsigned int off, unsigned int len, u8 rdt);

/**
 * pci_vpd_find_info_keyword - Locates an information field keyword in the VPD
 * @buf: Pointer to buffered vpd data
 * @off: The offset into the buffer at which to begin the search
 * @len: The length of the buffer area, relative to off, in which to search
 * @kw: The keyword to search for
 *
 * Returns the index where the information field keyword was found or
 * -ENOENT otherwise.
 */
int pci_vpd_find_info_keyword(const u8 *buf, unsigned int off,
			      unsigned int len, const char *kw);

/* PCI <-> OF binding helpers */
#ifdef CONFIG_OF
struct device_node;
extern void pci_set_of_node(struct pci_dev *dev);
extern void pci_release_of_node(struct pci_dev *dev);
extern void pci_set_bus_of_node(struct pci_bus *bus);
extern void pci_release_bus_of_node(struct pci_bus *bus);

/* Arch may override this (weak) */
extern struct device_node * __weak pcibios_get_phb_of_node(struct pci_bus *bus);

static inline struct device_node *pci_device_to_OF_node(struct pci_dev *pdev)
{
	return pdev ? pdev->dev.of_node : NULL;
}

static inline struct device_node *pci_bus_to_OF_node(struct pci_bus *bus)
{
	return bus ? bus->dev.of_node : NULL;
}

#else /* CONFIG_OF */
static inline void pci_set_of_node(struct pci_dev *dev) { }
static inline void pci_release_of_node(struct pci_dev *dev) { }
static inline void pci_set_bus_of_node(struct pci_bus *bus) { }
static inline void pci_release_bus_of_node(struct pci_bus *bus) { }
#endif  /* CONFIG_OF */

/**
 * pci_find_upstream_pcie_bridge - find upstream PCIe-to-PCI bridge of a device
 * @pdev: the PCI device
 *
 * if the device is PCIE, return NULL
 * if the device isn't connected to a PCIe bridge (that is its parent is a
 * legacy PCI bridge and the bridge is directly connected to bus 0), return its
 * parent
 */
struct pci_dev *pci_find_upstream_pcie_bridge(struct pci_dev *pdev);

#endif /* __KERNEL__ */
#endif /* LINUX_PCI_H */

/*
 * VLAN		An implementation of 802.1Q VLAN tagging.
 *
 * Authors:	Ben Greear <greearb@candelatech.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 */

#ifndef _LINUX_IF_VLAN_H_
#define _LINUX_IF_VLAN_H_

#ifdef __KERNEL__
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>

#define VLAN_HLEN	4		/* The additional bytes (on top of the Ethernet header)
					 * that VLAN requires.
					 */
#define VLAN_ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define VLAN_ETH_HLEN	18		/* Total octets in header.	 */
/*
sans:无，没有
以太网最小长度60字节，带vlan头后加4，所以带vlan帧的最小长度为64字节
*/
#define VLAN_ETH_ZLEN	64		/* Min. octets in frame sans FCS */

/*
 * According to 802.3ac, the packet can be 4 bytes longer. --Klika Jan
 */
/*
负载数据最大长度1500，与以太网一致
*/
#define VLAN_ETH_DATA_LEN	1500	/* Max. octets in payload	 */
/*
头部多了4字节vlan头，帧最大长度为1514+4
*/
#define VLAN_ETH_FRAME_LEN	1518	/* Max. octets in frame sans FCS */

/*
 * 	struct vlan_hdr - vlan header
 * 	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	/* Tag Control Information
	   包括高3bit优先级和低12bit的vlanid */
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

/**
 *	struct vlan_ethhdr - vlan ethernet header (ethhdr + vlan_hdr)
 *	@h_dest: destination ethernet address
 *	@h_source: source ethernet address
 *	@h_vlan_proto: ethernet protocol (always 0x8100)
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
/*
User Priority定义用户优先级，包括8个（2^3）优先级别，占3位
CFI占1位，Canonical Format Indicator规范格式指示器
VID(VLAN ID)是对VLAN的识别字段，为12位。
支持4096（2^12）VLAN的识别。
在4096可能的VID中，VID=0用于识别帧优先级。4095（FFF）作为预留值
所以VLAN配置的最大可能值为4094
*/
struct vlan_ethhdr {
	unsigned char	h_dest[ETH_ALEN];
	unsigned char	h_source[ETH_ALEN];
	__be16		h_vlan_proto;
	__be16		h_vlan_TCI;
	__be16		h_vlan_encapsulated_proto;
};

#include <linux/skbuff.h>

/*
辅助函数，用于从mac_header指针进行强制类型转换
*/
static inline struct vlan_ethhdr *vlan_eth_hdr(const struct sk_buff *skb)
{
	return (struct vlan_ethhdr *)skb_mac_header(skb);
}

/*
高3bit表示优先级，0-7
*/
#define VLAN_PRIO_MASK		0xe000 /* Priority Code Point */
#define VLAN_PRIO_SHIFT		13
/*
第13bit表示CFI，规范格式指示符
照目前内核代码的实现，该bit用于表示是否含有vlanid，1表示低12bit含有vlanid
*/
#define VLAN_CFI_MASK		0x1000 /* Canonical Format Indicator */
#define VLAN_TAG_PRESENT	VLAN_CFI_MASK
/*
低12bit表示vlanid
取值范围在0-4095之间，不包含0和4095，英文文档使用"between"一词
*/
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
#define VLAN_N_VID		4096

/* found in socket.c */
extern void vlan_ioctl_set(int (*hook)(struct net *, void __user *));

/* if this changes, algorithm will have to be reworked because this
 * depends on completely exhausting the VLAN identifier space.  Thus
 * it gives constant time look-up, but in many cases it wastes memory.
 */
/*
上面的注释是针对最初struct vlan_group中直接使用4096个struct net_device指针的情况
那样对vlan虚拟接口的查找是线性的，不过的确浪费了很多的指针空间

作为优化，将4096个vlan划分为8个区域
在struct vlan_group使用2级指针定位不同的区域，在对应区域的vlan没有使用时
潜在的便可以节约其余的7/8指针空间
*/
#define VLAN_GROUP_ARRAY_SPLIT_PARTS  8
/*
每个区域的vlan个数，512
*/
#define VLAN_GROUP_ARRAY_PART_LEN     (VLAN_N_VID/VLAN_GROUP_ARRAY_SPLIT_PARTS)

/*
同一个物理接口下的vlan虚接口用vlan_group结构描述
即每个物理接口可以对应一个vlan_group
*/
struct vlan_group {
	/* 该虚拟vlan接口组所依附的接口
	   可能是真实的物理接口，也完全有可能是另一个虚拟接口，比如bond接口 */
	struct net_device	*real_dev; /* The ethernet(like) device
					    * the vlan is attached to.
					    */
	/* 记录使用的vlan个数 */
	unsigned int		nr_vlans;
	struct hlist_node	hlist;	/* linked list */
	/* 虚拟vlan接口数组 */
	struct net_device **vlan_devices_arrays[VLAN_GROUP_ARRAY_SPLIT_PARTS];
	struct rcu_head		rcu;
};


/*
根据@dev的私有标记，判断此接口是否是一个虚拟vlan接口
生成新的虚拟vlan接口时，在vlan_setup()中会添加此标记
*/
static inline int is_vlan_dev(struct net_device *dev)
{
        return dev->priv_flags & IFF_802_1Q_VLAN;
}

/*
根据高第4bit位判断是否带有vlan
*/
#define vlan_tx_tag_present(__skb)	((__skb)->vlan_tci & VLAN_TAG_PRESENT)
/*
取TCI，skb->vlan_tci字段是包括优先级和vlanid的
*/
#define vlan_tx_tag_get(__skb)		((__skb)->vlan_tci & ~VLAN_TAG_PRESENT)

#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)

extern struct net_device *__vlan_find_dev_deep(struct net_device *real_dev,
					       u16 vlan_id);
extern struct net_device *vlan_dev_real_dev(const struct net_device *dev);
extern u16 vlan_dev_vlan_id(const struct net_device *dev);

extern bool vlan_do_receive(struct sk_buff **skb, bool last_handler);
extern struct sk_buff *vlan_untag(struct sk_buff *skb);

#else
static inline struct net_device *
__vlan_find_dev_deep(struct net_device *real_dev, u16 vlan_id)
{
	return NULL;
}

static inline struct net_device *vlan_dev_real_dev(const struct net_device *dev)
{
	BUG();
	return NULL;
}

static inline u16 vlan_dev_vlan_id(const struct net_device *dev)
{
	BUG();
	return 0;
}

static inline bool vlan_do_receive(struct sk_buff **skb, bool last_handler)
{
	/* 内核没有配置支持vlan时，带vlan的报文认为是其他主机的，不应做处理 */
	if (((*skb)->vlan_tci & VLAN_VID_MASK) && last_handler)
		(*skb)->pkt_type = PACKET_OTHERHOST;
	return false;
}

static inline struct sk_buff *vlan_untag(struct sk_buff *skb)
{
	return skb;
}
#endif

/**
 * vlan_insert_tag - regular VLAN tag inserting
 * @skb: skbuff to tag
 * @vlan_tci: VLAN TCI to insert
 *
 * Inserts the VLAN tag into @skb as part of the payload
 * Returns a VLAN tagged skb. If a new skb is created, @skb is freed.
 *
 * Following the skb_unshare() example, in case of error, the calling function
 * doesn't have to worry about freeing the original skb.
 *
 * Does not change skb->protocol so this function can be used during receive.
 */
/*
该函数假定@skb->data指向mac header，调用时需注意

如果申请新skb失败的话，原skb会被释放，所以调用者不用为释放原skb而担心
不会改变skb->protocol域的值，所以接收时也可使用该函数
*/
static inline struct sk_buff *vlan_insert_tag(struct sk_buff *skb, u16 vlan_tci)
{
	struct vlan_ethhdr *veth;

	if (skb_cow_head(skb, VLAN_HLEN) < 0) {
		kfree_skb(skb);
		return NULL;
	}
	veth = (struct vlan_ethhdr *)skb_push(skb, VLAN_HLEN);

	/* Move the mac addresses to the beginning of the new header. */
	memmove(skb->data, skb->data + VLAN_HLEN, 2 * VLAN_ETH_ALEN);
	skb->mac_header -= VLAN_HLEN;

	/* first, the ethernet type */
	veth->h_vlan_proto = htons(ETH_P_8021Q);

	/* now, the TCI */
	veth->h_vlan_TCI = htons(vlan_tci);

	return skb;
}

/**
 * __vlan_put_tag - regular VLAN tag inserting
 * @skb: skbuff to tag
 * @vlan_tci: VLAN TCI to insert
 *
 * Inserts the VLAN tag into @skb as part of the payload
 * Returns a VLAN tagged skb. If a new skb is created, @skb is freed.
 *
 * Following the skb_unshare() example, in case of error, the calling function
 * doesn't have to worry about freeing the original skb.
 */
/*
对vlan_insert_tag()进行一次封装
该函数修改skb->protocol字段
*/
static inline struct sk_buff *__vlan_put_tag(struct sk_buff *skb, u16 vlan_tci)
{
	skb = vlan_insert_tag(skb, vlan_tci);
	if (skb)
		skb->protocol = htons(ETH_P_8021Q);
	return skb;
}

/**
 * __vlan_hwaccel_put_tag - hardware accelerated VLAN inserting
 * @skb: skbuff to tag
 * @vlan_tci: VLAN TCI to insert
 *
 * Puts the VLAN TCI in @skb->vlan_tci and lets the device do the rest
 */
static inline struct sk_buff *__vlan_hwaccel_put_tag(struct sk_buff *skb,
						     u16 vlan_tci)
{
	/* 使用VLAN_TAG_PRESENT位标记含有vlanid
	   使用vlan_tci字段记录优先级和vlanid */
	skb->vlan_tci = VLAN_TAG_PRESENT | vlan_tci;
	return skb;
}

#define HAVE_VLAN_PUT_TAG

/**
 * vlan_put_tag - inserts VLAN tag according to device features
 * @skb: skbuff to tag
 * @vlan_tci: VLAN TCI to insert
 *
 * Assumes skb->dev is the target that will xmit this frame.
 * Returns a VLAN tagged skb.
 */
/*
根据接口特性将@vlan_tci信息添加到@skb中
*/
static inline struct sk_buff *vlan_put_tag(struct sk_buff *skb, u16 vlan_tci)
{
	/* 硬件支持发送时添加vlan，则只需将vlan信息标记在skb->vlan_tci字段 */
	if (skb->dev->features & NETIF_F_HW_VLAN_TX) {
		return __vlan_hwaccel_put_tag(skb, vlan_tci);
	/* 否则需要在软件层将以太网头前移，把vlan信息添加到帧中 */
	} else {
		return __vlan_put_tag(skb, vlan_tci);
	}
}

/**
 * __vlan_get_tag - get the VLAN ID that is part of the payload
 * @skb: skbuff to query
 * @vlan_tci: buffer to store vlaue
 *
 * Returns error if the skb is not of VLAN type
 */
static inline int __vlan_get_tag(const struct sk_buff *skb, u16 *vlan_tci)
{
	/* 注意是从skb->data指针开始解析 */
	struct vlan_ethhdr *veth = (struct vlan_ethhdr *)skb->data;

	if (veth->h_vlan_proto != htons(ETH_P_8021Q)) {
		return -EINVAL;
	}

	/* 保存vlan信息，包含优先级和vlanid */
	*vlan_tci = ntohs(veth->h_vlan_TCI);
	return 0;
}

/**
 * __vlan_hwaccel_get_tag - get the VLAN ID that is in @skb->cb[]
 * @skb: skbuff to query
 * @vlan_tci: buffer to store vlaue
 *
 * Returns error if @skb->vlan_tci is not set correctly
 */
/*
从@skb->vlan_tci字段提取vlan信息
*/
static inline int __vlan_hwaccel_get_tag(const struct sk_buff *skb,
					 u16 *vlan_tci)
{
	if (vlan_tx_tag_present(skb)) {
		*vlan_tci = vlan_tx_tag_get(skb);
		return 0;
	} else {
		*vlan_tci = 0;
		return -EINVAL;
	}
}

#define HAVE_VLAN_GET_TAG

/**
 * vlan_get_tag - get the VLAN ID from the skb
 * @skb: skbuff to query
 * @vlan_tci: buffer to store vlaue
 *
 * Returns error if the skb is not VLAN tagged
 */
/*
封装函数，根据硬件特性提取vlan信息
*/
static inline int vlan_get_tag(const struct sk_buff *skb, u16 *vlan_tci)
{
	if (skb->dev->features & NETIF_F_HW_VLAN_TX) {
		return __vlan_hwaccel_get_tag(skb, vlan_tci);
	} else {
		return __vlan_get_tag(skb, vlan_tci);
	}
}

/**
 * vlan_get_protocol - get protocol EtherType.
 * @skb: skbuff to query
 *
 * Returns the EtherType of the packet, regardless of whether it is
 * vlan encapsulated (normal or hardware accelerated) or not.
 */
/*
取vlan头中封装的以太网协议类型
*/
static inline __be16 vlan_get_protocol(const struct sk_buff *skb)
{
	__be16 protocol = 0;

	if (vlan_tx_tag_present(skb) ||
	     skb->protocol != cpu_to_be16(ETH_P_8021Q))
		protocol = skb->protocol;
	else {
		__be16 proto, *protop;
		protop = skb_header_pointer(skb, offsetof(struct vlan_ethhdr,
						h_vlan_encapsulated_proto),
						sizeof(proto), &proto);
		if (likely(protop))
			protocol = *protop;
	}

	return protocol;
}
#endif /* __KERNEL__ */

/* VLAN IOCTLs are found in sockios.h */

/* Passed in vlan_ioctl_args structure to determine behaviour. */
enum vlan_ioctl_cmds {
	ADD_VLAN_CMD,
	DEL_VLAN_CMD,
	SET_VLAN_INGRESS_PRIORITY_CMD,
	SET_VLAN_EGRESS_PRIORITY_CMD,
	GET_VLAN_INGRESS_PRIORITY_CMD,
	GET_VLAN_EGRESS_PRIORITY_CMD,
	SET_VLAN_NAME_TYPE_CMD,
	SET_VLAN_FLAG_CMD,
	GET_VLAN_REALDEV_NAME_CMD, /* If this works, you know it's a VLAN device, btw */
	GET_VLAN_VID_CMD /* Get the VID of this VLAN (specified by name) */
};

enum vlan_flags {
	VLAN_FLAG_REORDER_HDR	= 0x1,
	VLAN_FLAG_GVRP		= 0x2,
	VLAN_FLAG_LOOSE_BINDING	= 0x4,
};

enum vlan_name_types {
	VLAN_NAME_TYPE_PLUS_VID, /* Name will look like:  vlan0005 */
	VLAN_NAME_TYPE_RAW_PLUS_VID, /* name will look like:  eth1.0005 */
	VLAN_NAME_TYPE_PLUS_VID_NO_PAD, /* Name will look like:  vlan5 */
	VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD, /* Name will look like:  eth0.5 */
	VLAN_NAME_TYPE_HIGHEST
};

struct vlan_ioctl_args {
	int cmd; /* Should be one of the vlan_ioctl_cmds enum above. */
	/* 物理接口名称 */
	char device1[24];

        union {
		char device2[24];
		int VID;
		unsigned int skb_priority;
		unsigned int name_type;
		unsigned int bind_type;
		unsigned int flag; /* Matches vlan_dev_info flags */
        } u;

	short vlan_qos;   
};

#endif /* !(_LINUX_IF_VLAN_H_) */

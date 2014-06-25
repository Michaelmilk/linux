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

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/bug.h>
#include <uapi/linux/if_vlan.h>

#define VLAN_HLEN	4		/* The additional bytes required by VLAN
					 * (in addition to the Ethernet header)
					 */
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
 *	@h_vlan_proto: ethernet protocol
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

/*
根据@dev的私有标记，判断此接口是否是一个虚拟vlan接口
生成新的虚拟vlan接口时，在vlan_setup()中会添加此标记
*/

static inline bool is_vlan_dev(struct net_device *dev)
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
#define vlan_tx_tag_get_id(__skb)	((__skb)->vlan_tci & VLAN_VID_MASK)

/**
 *	struct vlan_pcpu_stats - VLAN percpu rx/tx stats
 *	@rx_packets: number of received packets
 *	@rx_bytes: number of received bytes
 *	@rx_multicast: number of received multicast packets
 *	@tx_packets: number of transmitted packets
 *	@tx_bytes: number of transmitted bytes
 *	@syncp: synchronization point for 64bit counters
 *	@rx_errors: number of rx errors
 *	@tx_dropped: number of tx drops
 */
struct vlan_pcpu_stats {
	u64			rx_packets;
	u64			rx_bytes;
	u64			rx_multicast;
	u64			tx_packets;
	u64			tx_bytes;
	struct u64_stats_sync	syncp;
	u32			rx_errors;
	u32			tx_dropped;
};

#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)

extern struct net_device *__vlan_find_dev_deep_rcu(struct net_device *real_dev,
					       __be16 vlan_proto, u16 vlan_id);
extern struct net_device *vlan_dev_real_dev(const struct net_device *dev);
extern u16 vlan_dev_vlan_id(const struct net_device *dev);
extern __be16 vlan_dev_vlan_proto(const struct net_device *dev);

/**
 *	struct vlan_priority_tci_mapping - vlan egress priority mappings
 *	@priority: skb priority
 *	@vlan_qos: vlan priority: (skb->priority << 13) & 0xE000
 *	@next: pointer to next struct
 */
struct vlan_priority_tci_mapping {
	u32					priority;
	u16					vlan_qos;
	struct vlan_priority_tci_mapping	*next;
};

struct proc_dir_entry;
struct netpoll;

/*
vlan接口的私有结构信息
*/

/**
 *	struct vlan_dev_priv - VLAN private device data
 *	@nr_ingress_mappings: number of ingress priority mappings
 *	@ingress_priority_map: ingress priority mappings
 *	@nr_egress_mappings: number of egress priority mappings
 *	@egress_priority_map: hash of egress priority mappings
 *	@vlan_proto: VLAN encapsulation protocol
 *	@vlan_id: VLAN identifier
 *	@flags: device flags
 *	@real_dev: underlying netdevice
 *	@real_dev_addr: address of underlying netdevice
 *	@dent: proc dir entry
 *	@vlan_pcpu_stats: ptr to percpu rx stats
 */
struct vlan_dev_priv {
	unsigned int				nr_ingress_mappings;
	u32					ingress_priority_map[8];
	unsigned int				nr_egress_mappings;
	struct vlan_priority_tci_mapping	*egress_priority_map[16];

	__be16					vlan_proto;
	u16					vlan_id;
	u16					flags;

	struct net_device			*real_dev;
	unsigned char				real_dev_addr[ETH_ALEN];

	struct proc_dir_entry			*dent;
	struct vlan_pcpu_stats __percpu		*vlan_pcpu_stats;
#ifdef CONFIG_NET_POLL_CONTROLLER
	struct netpoll				*netpoll;
#endif
	unsigned int				nest_level;
};

/*
vlan接口net_device的私有指针指向一个struct vlan_dev_priv结构
*/

static inline struct vlan_dev_priv *vlan_dev_priv(const struct net_device *dev)
{
	return netdev_priv(dev);
}

static inline u16
vlan_dev_get_egress_qos_mask(struct net_device *dev, u32 skprio)
{
	struct vlan_priority_tci_mapping *mp;

	smp_rmb(); /* coupled with smp_wmb() in vlan_dev_set_egress_priority() */

	mp = vlan_dev_priv(dev)->egress_priority_map[(skprio & 0xF)];
	while (mp) {
		if (mp->priority == skprio) {
			return mp->vlan_qos; /* This should already be shifted
					      * to mask correctly with the
					      * VLAN's TCI */
		}
		mp = mp->next;
	}
	return 0;
}

extern bool vlan_do_receive(struct sk_buff **skb);
extern struct sk_buff *vlan_untag(struct sk_buff *skb);

extern int vlan_vid_add(struct net_device *dev, __be16 proto, u16 vid);
extern void vlan_vid_del(struct net_device *dev, __be16 proto, u16 vid);

extern int vlan_vids_add_by_dev(struct net_device *dev,
				const struct net_device *by_dev);
extern void vlan_vids_del_by_dev(struct net_device *dev,
				 const struct net_device *by_dev);

extern bool vlan_uses_dev(const struct net_device *dev);

static inline int vlan_get_encap_level(struct net_device *dev)
{
	BUG_ON(!is_vlan_dev(dev));
	return vlan_dev_priv(dev)->nest_level;
}
#else
static inline struct net_device *
__vlan_find_dev_deep_rcu(struct net_device *real_dev,
		     __be16 vlan_proto, u16 vlan_id)
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

static inline __be16 vlan_dev_vlan_proto(const struct net_device *dev)
{
	BUG();
	return 0;
}

static inline u16 vlan_dev_get_egress_qos_mask(struct net_device *dev,
					       u32 skprio)
{
	return 0;
}

static inline bool vlan_do_receive(struct sk_buff **skb)
{
	return false;
}

static inline struct sk_buff *vlan_untag(struct sk_buff *skb)
{
	return skb;
}

static inline int vlan_vid_add(struct net_device *dev, __be16 proto, u16 vid)
{
	return 0;
}

static inline void vlan_vid_del(struct net_device *dev, __be16 proto, u16 vid)
{
}

static inline int vlan_vids_add_by_dev(struct net_device *dev,
				       const struct net_device *by_dev)
{
	return 0;
}

static inline void vlan_vids_del_by_dev(struct net_device *dev,
					const struct net_device *by_dev)
{
}

static inline bool vlan_uses_dev(const struct net_device *dev)
{
	return false;
}
static inline int vlan_get_encap_level(struct net_device *dev)
{
	BUG();
	return 0;
}
#endif

static inline bool vlan_hw_offload_capable(netdev_features_t features,
					   __be16 proto)
{
	if (proto == htons(ETH_P_8021Q) && features & NETIF_F_HW_VLAN_CTAG_TX)
		return true;
	if (proto == htons(ETH_P_8021AD) && features & NETIF_F_HW_VLAN_STAG_TX)
		return true;
	return false;
}

/*
该函数假定@skb->data指向mac header，调用时需注意

如果申请新skb失败的话，原skb会被释放，所以调用者不用为释放原skb而担心
不会改变skb->protocol域的值，所以接收时也可使用该函数
*/

/**
 * vlan_insert_tag - regular VLAN tag inserting
 * @skb: skbuff to tag
 * @vlan_proto: VLAN encapsulation protocol
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
static inline struct sk_buff *vlan_insert_tag(struct sk_buff *skb,
					      __be16 vlan_proto, u16 vlan_tci)
{
	struct vlan_ethhdr *veth;

	if (skb_cow_head(skb, VLAN_HLEN) < 0) {
		dev_kfree_skb_any(skb);
		return NULL;
	}
	veth = (struct vlan_ethhdr *)skb_push(skb, VLAN_HLEN);

	/* Move the mac addresses to the beginning of the new header. */
	memmove(skb->data, skb->data + VLAN_HLEN, 2 * ETH_ALEN);
	skb->mac_header -= VLAN_HLEN;

	/* first, the ethernet type */
	veth->h_vlan_proto = vlan_proto;

	/* now, the TCI */
	veth->h_vlan_TCI = htons(vlan_tci);

	return skb;
}

/*
对vlan_insert_tag()进行一次封装
该函数修改skb->protocol字段
*/

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
static inline struct sk_buff *__vlan_put_tag(struct sk_buff *skb,
					     __be16 vlan_proto, u16 vlan_tci)
{
	skb = vlan_insert_tag(skb, vlan_proto, vlan_tci);
	if (skb)
		skb->protocol = vlan_proto;
	return skb;
}

/**
 * __vlan_hwaccel_put_tag - hardware accelerated VLAN inserting
 * @skb: skbuff to tag
 * @vlan_proto: VLAN encapsulation protocol
 * @vlan_tci: VLAN TCI to insert
 *
 * Puts the VLAN TCI in @skb->vlan_tci and lets the device do the rest
 */
static inline struct sk_buff *__vlan_hwaccel_put_tag(struct sk_buff *skb,
						     __be16 vlan_proto,
						     u16 vlan_tci)
{
	skb->vlan_proto = vlan_proto;
	/* 使用VLAN_TAG_PRESENT位标记含有vlanid
	   使用vlan_tci字段记录优先级和vlanid */
	skb->vlan_tci = VLAN_TAG_PRESENT | vlan_tci;
	return skb;
}

/*
根据接口特性将@vlan_tci信息添加到@skb中
*/

/**
 * vlan_put_tag - inserts VLAN tag according to device features
 * @skb: skbuff to tag
 * @vlan_tci: VLAN TCI to insert
 *
 * Assumes skb->dev is the target that will xmit this frame.
 * Returns a VLAN tagged skb.
 */
static inline struct sk_buff *vlan_put_tag(struct sk_buff *skb,
					   __be16 vlan_proto, u16 vlan_tci)
{
	/* 硬件支持发送时添加vlan，则只需将vlan信息标记在skb->vlan_tci字段 */
	if (vlan_hw_offload_capable(skb->dev->features, vlan_proto)) {
		return __vlan_hwaccel_put_tag(skb, vlan_proto, vlan_tci);
	} else {
		/* 否则需要在软件层将以太网头前移，把vlan信息添加到帧中 */
		return __vlan_put_tag(skb, vlan_proto, vlan_tci);
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

	if (veth->h_vlan_proto != htons(ETH_P_8021Q) &&
	    veth->h_vlan_proto != htons(ETH_P_8021AD))
		return -EINVAL;

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
	if (skb->dev->features & NETIF_F_HW_VLAN_CTAG_TX) {
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

/*
设置skb->protocol为vlan头后的协议类型
*/
static inline void vlan_set_encap_proto(struct sk_buff *skb,
					struct vlan_hdr *vhdr)
{
	__be16 proto;
	unsigned short *rawp;

	/*
	 * Was a VLAN packet, grab the encapsulated protocol, which the layer
	 * three protocols care about.
	 */

	proto = vhdr->h_vlan_encapsulated_proto;
	if (ntohs(proto) >= ETH_P_802_3_MIN) {
		skb->protocol = proto;
		return;
	}

	rawp = (unsigned short *)(vhdr + 1);
	if (*rawp == 0xFFFF)
		/*
		 * This is a magic hack to spot IPX packets. Older Novell
		 * breaks the protocol design and runs IPX over 802.3 without
		 * an 802.2 LLC layer. We look for FFFF which isn't a used
		 * 802.2 SSAP/DSAP. This won't work for fault tolerant netware
		 * but does for the rest.
		 */
		skb->protocol = htons(ETH_P_802_3);
	else
		/*
		 * Real 802.2 LLC
		 */
		skb->protocol = htons(ETH_P_802_2);
}

#endif /* !(_LINUX_IF_VLAN_H_) */

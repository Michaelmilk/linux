#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/netpoll.h>
#include "vlan.h"

/*
由vlan接口接收此skb
参数为2级指针，因为共享性检查中和插入vlanid时可能会分配新的skb
*/
bool vlan_do_receive(struct sk_buff **skbp)
{
	struct sk_buff *skb = *skbp;
	u16 vlan_id = skb->vlan_tci & VLAN_VID_MASK;
	struct net_device *vlan_dev;
	struct vlan_pcpu_stats *rx_stats;

	/* 查找虚拟vlan接口 */
	vlan_dev = vlan_find_dev(skb->dev, vlan_id);
	if (!vlan_dev) {
		if (vlan_id)
			skb->pkt_type = PACKET_OTHERHOST;
		/* 没有对应vlan_id的虚拟接口，而该帧又是vlan帧
		   则标记为PACKET_OTHERHOST，返回false，表示本机vlan未做处理 */
		return false;
	}

	/* 检查skb的共享性
	   参考__netif_receive_skb()中调用vlan_do_receive()前的deliver_skb()*/
	skb = *skbp = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		return false;

	/* 接收接口改为虚拟的vlan接口 */
	skb->dev = vlan_dev;
	if (skb->pkt_type == PACKET_OTHERHOST) {
		/* Our lower layer thinks this is not local, let's make sure.
		 * This allows the VLAN to have a different MAC than the
		 * underlying device, and still route correctly. */
		/* 修正底层协议栈对目的mac的检查
		   主要是驱动中使用eth_type_trans()的结果 */
		if (!compare_ether_addr(eth_hdr(skb)->h_dest,
					vlan_dev->dev_addr))
			skb->pkt_type = PACKET_HOST;
	}

	if (!(vlan_dev_info(vlan_dev)->flags & VLAN_FLAG_REORDER_HDR)) {
		unsigned int offset = skb->data - skb_mac_header(skb);

		/*
		 * vlan_insert_tag expect skb->data pointing to mac header.
		 * So change skb->data before calling it and change back to
		 * original position later
		 */
		skb_push(skb, offset);
		skb = *skbp = vlan_insert_tag(skb, skb->vlan_tci);
		if (!skb)
			return false;
		skb_pull(skb, offset + VLAN_HLEN);
		skb_reset_mac_len(skb);
	}

	skb->priority = vlan_get_ingress_priority(vlan_dev, skb->vlan_tci);
	/* 记录的vlanid清0，因为已经选择到了对应的虚拟vlan接口
	   该虚拟的vlan接口所对应的vlanid是已知的 */
	skb->vlan_tci = 0;

	rx_stats = this_cpu_ptr(vlan_dev_info(vlan_dev)->vlan_pcpu_stats);

	u64_stats_update_begin(&rx_stats->syncp);
	rx_stats->rx_packets++;
	rx_stats->rx_bytes += skb->len;
	if (skb->pkt_type == PACKET_MULTICAST)
		rx_stats->rx_multicast++;
	u64_stats_update_end(&rx_stats->syncp);

	/* 返回true，表示该vlan报文成功处理，将会重进协议栈 */
	return true;
}

struct net_device *vlan_dev_real_dev(const struct net_device *dev)
{
	return vlan_dev_info(dev)->real_dev;
}
EXPORT_SYMBOL(vlan_dev_real_dev);

u16 vlan_dev_vlan_id(const struct net_device *dev)
{
	return vlan_dev_info(dev)->vlan_id;
}
EXPORT_SYMBOL(vlan_dev_vlan_id);

/* VLAN rx hw acceleration helper.  This acts like netif_{rx,receive_skb}(). */
/*
网卡硬件支持加减vlan的时候
在接收时已经将vlanid从帧中剥除，由驱动将vlan信息添加到skb->vlan_tci字段

@polling	: 根据接收模式调用不同的接收函数，NAPI或non-NAPI
*/
int __vlan_hwaccel_rx(struct sk_buff *skb, struct vlan_group *grp,
		      u16 vlan_tci, int polling)
{
	__vlan_hwaccel_put_tag(skb, vlan_tci);
	return polling ? netif_receive_skb(skb) : netif_rx(skb);
}
EXPORT_SYMBOL(__vlan_hwaccel_rx);

gro_result_t vlan_gro_receive(struct napi_struct *napi, struct vlan_group *grp,
			      unsigned int vlan_tci, struct sk_buff *skb)
{
	__vlan_hwaccel_put_tag(skb, vlan_tci);
	return napi_gro_receive(napi, skb);
}
EXPORT_SYMBOL(vlan_gro_receive);

gro_result_t vlan_gro_frags(struct napi_struct *napi, struct vlan_group *grp,
			    unsigned int vlan_tci)
{
	__vlan_hwaccel_put_tag(napi->skb, vlan_tci);
	return napi_gro_frags(napi);
}
EXPORT_SYMBOL(vlan_gro_frags);

/*
将以太网头的源和目的mac的12个字节后移4字节，去掉vlan头
*/
static struct sk_buff *vlan_reorder_header(struct sk_buff *skb)
{
	if (skb_cow(skb, skb_headroom(skb)) < 0)
		return NULL;
	memmove(skb->data - ETH_HLEN, skb->data - VLAN_ETH_HLEN, 2 * ETH_ALEN);
	skb->mac_header += VLAN_HLEN;
	skb_reset_mac_len(skb);
	return skb;
}

/*
去掉了VLAN头后，修改skb->protocol字段记录的协议为原VLAN头封装的协议类型
*/
static void vlan_set_encap_proto(struct sk_buff *skb, struct vlan_hdr *vhdr)
{
	__be16 proto;
	unsigned char *rawp;

	/*
	 * Was a VLAN packet, grab the encapsulated protocol, which the layer
	 * three protocols care about.
	 */

	proto = vhdr->h_vlan_encapsulated_proto;
	if (ntohs(proto) >= 1536) {
		skb->protocol = proto;
		return;
	}

	rawp = skb->data;
	if (*(unsigned short *) rawp == 0xFFFF)
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

/*
去掉vlan报文的vlan头，vlanid提取出来后保存在skb->vlan_tci字段
*/
struct sk_buff *vlan_untag(struct sk_buff *skb)
{
	struct vlan_hdr *vhdr;
	u16 vlan_tci;

	if (unlikely(vlan_tx_tag_present(skb))) {
		/* vlan_tci is already set-up so leave this for another time */
		return skb;
	}

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		goto err_free;

	if (unlikely(!pskb_may_pull(skb, VLAN_HLEN)))
		goto err_free;

	/* vlan_hdr指针从data域开始转换
	   所以在调用vlan_untag()函数时要注意skb已经pull过ETH_HLEN */
	vhdr = (struct vlan_hdr *) skb->data;
	vlan_tci = ntohs(vhdr->h_vlan_TCI);
	__vlan_hwaccel_put_tag(skb, vlan_tci);

	skb_pull_rcsum(skb, VLAN_HLEN);
	vlan_set_encap_proto(skb, vhdr);

	skb = vlan_reorder_header(skb);
	if (unlikely(!skb))
		goto err_free;

	return skb;

err_free:
	kfree_skb(skb);
	return NULL;
}

/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) module.
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *
 *
 * Fixes:
 *		Alan Cox	:	Commented a couple of minor bits of surplus code
 *		Alan Cox	:	Undefining IP_FORWARD doesn't include the code
 *					(just stops a compiler warning).
 *		Alan Cox	:	Frames with >=MAX_ROUTE record routes, strict routes or loose routes
 *					are junked rather than corrupting things.
 *		Alan Cox	:	Frames to bad broadcast subnets are dumped
 *					We used to process them non broadcast and
 *					boy could that cause havoc.
 *		Alan Cox	:	ip_forward sets the free flag on the
 *					new frame it queues. Still crap because
 *					it copies the frame but at least it
 *					doesn't eat memory too.
 *		Alan Cox	:	Generic queue code and memory fixes.
 *		Fred Van Kempen :	IP fragment support (borrowed from NET2E)
 *		Gerhard Koerting:	Forward fragmented frames correctly.
 *		Gerhard Koerting: 	Fixes to my fix of the above 8-).
 *		Gerhard Koerting:	IP interface addressing fix.
 *		Linus Torvalds	:	More robustness checks
 *		Alan Cox	:	Even more checks: Still not as robust as it ought to be
 *		Alan Cox	:	Save IP header pointer for later
 *		Alan Cox	:	ip option setting
 *		Alan Cox	:	Use ip_tos/ip_ttl settings
 *		Alan Cox	:	Fragmentation bogosity removed
 *					(Thanks to Mark.Bush@prg.ox.ac.uk)
 *		Dmitry Gorodchanin :	Send of a raw packet crash fix.
 *		Alan Cox	:	Silly ip bug when an overlength
 *					fragment turns up. Now frees the
 *					queue.
 *		Linus Torvalds/ :	Memory leakage on fragmentation
 *		Alan Cox	:	handling.
 *		Gerhard Koerting:	Forwarding uses IP priority hints
 *		Teemu Rantanen	:	Fragment problems.
 *		Alan Cox	:	General cleanup, comments and reformat
 *		Alan Cox	:	SNMP statistics
 *		Alan Cox	:	BSD address rule semantics. Also see
 *					UDP as there is a nasty checksum issue
 *					if you do things the wrong way.
 *		Alan Cox	:	Always defrag, moved IP_FORWARD to the config.in file
 *		Alan Cox	: 	IP options adjust sk->priority.
 *		Pedro Roque	:	Fix mtu/length error in ip_forward.
 *		Alan Cox	:	Avoid ip_chk_addr when possible.
 *	Richard Underwood	:	IP multicasting.
 *		Alan Cox	:	Cleaned up multicast handlers.
 *		Alan Cox	:	RAW sockets demultiplex in the BSD style.
 *		Gunther Mayer	:	Fix the SNMP reporting typo
 *		Alan Cox	:	Always in group 224.0.0.1
 *	Pauline Middelink	:	Fast ip_checksum update when forwarding
 *					Masquerading support.
 *		Alan Cox	:	Multicast loopback error for 224.0.0.1
 *		Alan Cox	:	IP_MULTICAST_LOOP option.
 *		Alan Cox	:	Use notifiers.
 *		Bjorn Ekwall	:	Removed ip_csum (from slhc.c too)
 *		Bjorn Ekwall	:	Moved ip_fast_csum to ip.h (inline!)
 *		Stefan Becker   :       Send out ICMP HOST REDIRECT
 *	Arnt Gulbrandsen	:	ip_build_xmit
 *		Alan Cox	:	Per socket routing cache
 *		Alan Cox	:	Fixed routing cache, added header cache.
 *		Alan Cox	:	Loopback didn't work right in original ip_build_xmit - fixed it.
 *		Alan Cox	:	Only send ICMP_REDIRECT if src/dest are the same net.
 *		Alan Cox	:	Incoming IP option handling.
 *		Alan Cox	:	Set saddr on raw output frames as per BSD.
 *		Alan Cox	:	Stopped broadcast source route explosions.
 *		Alan Cox	:	Can disable source routing
 *		Takeshi Sone    :	Masquerading didn't work.
 *	Dave Bonn,Alan Cox	:	Faster IP forwarding whenever possible.
 *		Alan Cox	:	Memory leaks, tramples, misc debugging.
 *		Alan Cox	:	Fixed multicast (by popular demand 8))
 *		Alan Cox	:	Fixed forwarding (by even more popular demand 8))
 *		Alan Cox	:	Fixed SNMP statistics [I think]
 *	Gerhard Koerting	:	IP fragmentation forwarding fix
 *		Alan Cox	:	Device lock against page fault.
 *		Alan Cox	:	IP_HDRINCL facility.
 *	Werner Almesberger	:	Zero fragment bug
 *		Alan Cox	:	RAW IP frame length bug
 *		Alan Cox	:	Outgoing firewall on build_xmit
 *		A.N.Kuznetsov	:	IP_OPTIONS support throughout the kernel
 *		Alan Cox	:	Multicast routing hooks
 *		Jos Vos		:	Do accounting *before* call_in_firewall
 *	Willy Konynenberg	:	Transparent proxying support
 *
 *
 *
 * To Fix:
 *		IP fragmentation wants rewriting cleanly. The RFC815 algorithm is much more efficient
 *		and could be made very efficient with the addition of some virtual memory hacks to permit
 *		the allocation of a buffer that can then be 'grown' by twiddling page tables.
 *		Output fragmentation wants updating along with the buffer management to use a single
 *		interleaved copy algorithm so that fragmenting has a one copy overhead. Actual packet
 *		output should probably do its own fragmentation at the UDP/RAW layer. TCP shouldn't cause
 *		fragmentation anyway.
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>

#include <linux/net.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <net/xfrm.h>
#include <linux/mroute.h>
#include <linux/netlink.h>

/*
 *	Process Router Attention IP option (RFC 2113)
 */
bool ip_call_ra_chain(struct sk_buff *skb)
{
	struct ip_ra_chain *ra;
	u8 protocol = ip_hdr(skb)->protocol;
	struct sock *last = NULL;
	struct net_device *dev = skb->dev;

	for (ra = rcu_dereference(ip_ra_chain); ra; ra = rcu_dereference(ra->next)) {
		struct sock *sk = ra->sk;

		/* If socket is bound to an interface, only report
		 * the packet if it came  from that interface.
		 */
		if (sk && inet_sk(sk)->inet_num == protocol &&
		    (!sk->sk_bound_dev_if ||
		     sk->sk_bound_dev_if == dev->ifindex) &&
		    net_eq(sock_net(sk), dev_net(dev))) {
			if (ip_is_fragment(ip_hdr(skb))) {
				if (ip_defrag(skb, IP_DEFRAG_CALL_RA_CHAIN))
					return true;
			}
			if (last) {
				struct sk_buff *skb2 = skb_clone(skb, GFP_ATOMIC);
				if (skb2)
					raw_rcv(last, skb2);
			}
			last = sk;
		}
	}

	if (last) {
		raw_rcv(last, skb);
		return true;
	}
	return false;
}

/*
向上层协议栈传递
到达传输层
*/
static int ip_local_deliver_finish(struct sk_buff *skb)
{
	/* 接收报文的设备所属命名空间 */
	struct net *net = dev_net(skb->dev);

	/* skb的data指针指向L4传输层数据起始位置 */
	__skb_pull(skb, ip_hdrlen(skb));

	/* Point into the IP datagram, just past the header. */
	/* 根据data指针设置transport_header指针 */
	skb_reset_transport_header(skb);

	rcu_read_lock();
	{
		/* IP头中携带的传输层协议类型
		   例如IPPROTO_TCP IPPROTO_UDP
		*/
		int protocol = ip_hdr(skb)->protocol;
		const struct net_protocol *ipprot;
		int raw;

	resubmit:
		raw = raw_local_deliver(skb, protocol);

		/* 取对应协议处理结构
		   例如tcp_protocol udp_protocol
		*/
		ipprot = rcu_dereference(inet_protos[protocol]);
		/* 对应的传输层协议有注册 */
		if (ipprot != NULL) {
			int ret;

			/* 有检查策略 */
			if (!ipprot->no_policy) {
				if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					kfree_skb(skb);
					goto out;
				}
				nf_reset(skb);
			}
			/* 调用传输层协议对应的处理函数
			   例如tcp_v4_rcv() udp_rcv()
			*/
			ret = ipprot->handler(skb);
			if (ret < 0) {
				protocol = -ret;
				goto resubmit;
			}
			IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
		} else {
			if (!raw) {
				if (xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb)) {
					IP_INC_STATS_BH(net, IPSTATS_MIB_INUNKNOWNPROTOS);
					/* 回送不可达 */
					icmp_send(skb, ICMP_DEST_UNREACH,
						  ICMP_PROT_UNREACH, 0);
				}
				kfree_skb(skb);
			} else {
				IP_INC_STATS_BH(net, IPSTATS_MIB_INDELIVERS);
				consume_skb(skb);
			}
		}
	}
 out:
	rcu_read_unlock();

	return 0;
}

/*
 * 	Deliver IP Packets to the higher protocol layers.
 */
/*
将IP报文送交给更高层的协议
首先对分片的数据包重组，然后转入netfilter的NF_INET_LOCAL_IN的hook点，
调用所有在该点注册的hook函数。
之后调用ip_local_deliver_finish()，进入第四层。
*/
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */

	/* 是IP分片报文
	   IP_MF	: 分片报文标记
	   IP_OFFSET: offset中的值记录该分片报文在这个大包中IP payload的位置
	   同一个分片报文的id字段值一致 */
	if (ip_is_fragment(ip_hdr(skb))) {
		/* 组片完成后返回0，进入下面的NF_HOOK()流程
		   ipq分配失败或者分片未接收完成
		   会返回一个负数，不继续向上层协议栈递交 */
		if (ip_defrag(skb, IP_DEFRAG_LOCAL_DELIVER))
			return 0;
	}

	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}

/*
解析IP头中的选项内容
*/
static inline bool ip_rcv_options(struct sk_buff *skb)
{
	struct ip_options *opt;
	const struct iphdr *iph;
	/* 接收报文的接口 */
	struct net_device *dev = skb->dev;

	/* It looks as overkill, because not all
	   IP options require packet mangling.
	   But it is the easiest for now, especially taking
	   into account that combination of IP options
	   and running sniffer is extremely rare condition.
					      --ANK (980813)
	*/
	if (skb_cow(skb, skb_headroom(skb))) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	/* 取IP头 */
	iph = ip_hdr(skb);
	/* 使用cb字段保存options信息 */
	opt = &(IPCB(skb)->opt);
	/* 记录选项数据长度 */
	opt->optlen = iph->ihl*4 - sizeof(struct iphdr);

	/* 解析选项信息 */
	if (ip_options_compile(dev_net(dev), opt, skb)) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
		goto drop;
	}

	if (unlikely(opt->srr)) {
		struct in_device *in_dev = __in_dev_get_rcu(dev);

		if (in_dev) {
			if (!IN_DEV_SOURCE_ROUTE(in_dev)) {
				if (IN_DEV_LOG_MARTIANS(in_dev))
					net_info_ratelimited("source route option %pI4 -> %pI4\n",
							     &iph->saddr,
							     &iph->daddr);
				goto drop;
			}
		}

		if (ip_options_rcv_srr(skb))
			goto drop;
	}

	return false;
drop:
	return true;
}

int sysctl_ip_early_demux __read_mostly = 1;
EXPORT_SYMBOL(sysctl_ip_early_demux);

static int ip_rcv_finish(struct sk_buff *skb)
{
	/* 取ip头指针 */
	const struct iphdr *iph = ip_hdr(skb);
	struct rtable *rt;

	if (sysctl_ip_early_demux && !skb_dst(skb)) {
		const struct net_protocol *ipprot;
		int protocol = iph->protocol;

		ipprot = rcu_dereference(inet_protos[protocol]);
		if (ipprot && ipprot->early_demux) {
			ipprot->early_demux(skb);
			/* must reload iph, skb->head might have changed */
			iph = ip_hdr(skb);
		}
	}

	/*
	 *	Initialise the virtual path cache for the packet. It describes
	 *	how the packet travels inside Linux networking.
	 */
	if (!skb_dst(skb)) {
		int err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
					       iph->tos, skb->dev);
		if (unlikely(err)) {
			/* 统计信息 */
			if (err == -EXDEV)
				NET_INC_STATS_BH(dev_net(skb->dev),
						 LINUX_MIB_IPRPFILTER);
			goto drop;
		}
	}

#ifdef CONFIG_IP_ROUTE_CLASSID
	if (unlikely(skb_dst(skb)->tclassid)) {
		struct ip_rt_acct *st = this_cpu_ptr(ip_rt_acct);
		u32 idx = skb_dst(skb)->tclassid;
		st[idx&0xFF].o_packets++;
		st[idx&0xFF].o_bytes += skb->len;
		st[(idx>>16)&0xFF].i_packets++;
		st[(idx>>16)&0xFF].i_bytes += skb->len;
	}
#endif

	/* 到这里已经得出了该@skb的路由信息
	   是发往本地ip_local_deliver()
	   还是进行转发ip_forward()
	   没有路由则为ip_error()
	*/

	/* 该ip包有选项数据，解析之 */
	if (iph->ihl > 5 && ip_rcv_options(skb))
		goto drop;

	/* 取rtable结构 */
	rt = skb_rtable(skb);
	/* 统计数据 */
	if (rt->rt_type == RTN_MULTICAST) {
		IP_UPD_PO_STATS_BH(dev_net(rt->dst.dev), IPSTATS_MIB_INMCAST,
				skb->len);
	} else if (rt->rt_type == RTN_BROADCAST)
		IP_UPD_PO_STATS_BH(dev_net(rt->dst.dev), IPSTATS_MIB_INBCAST,
				skb->len);

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}

/*
 * 	Main IP Receive routine.
 */
/*
对传递上来的IP协议报文做一些基本的检查工作

首先进入netfilter框架下IP层的NF_IP_PRE_ROUTING的hook点
调用所有在该点注册的hook函数
例如conntrack

最后会调用ip_rcv_finish()
*/
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	const struct iphdr *iph;
	u32 len;

	/* When the interface is in promisc. mode, drop all the crap
	 * that it receives, do not try to analyse it.
	 */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;


	IP_UPD_PO_STATS_BH(dev_net(dev), IPSTATS_MIB_IN, skb->len);

	/* 如果skb->users!=1，则clone一个skb
	   如果该skb被ptype_all链上注册的ETH_P_ALL类型回调函数处理过
	   或是被同类型的回调函数处理过，则该skb是共享的
	   在deliver_skb()中增加了users计数 */
	if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto out;
	}

	/* 数据至少要达到IP头的长度
	   如果是非线性的，则会把数据提取到线性区 */
	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		goto inhdr_error;

	/* 取IP头指针 */
	iph = ip_hdr(skb);

	/*
	 *	RFC1122: 3.2.1.2 MUST silently discard any IP frame that fails the checksum.
	 *
	 *	Is the datagram acceptable?
	 *
	 *	1.	Length at least the size of an ip header
	 *	2.	Version of 4
	 *	3.	Checksums correctly. [Speed optimisation for later, skip loopback checksums]
	 *	4.	Doesn't have a bogus length
	 */

	/* IP头中携带的数据检查 */
	if (iph->ihl < 5 || iph->version != 4)
		goto inhdr_error;

	/* 数据内容要达到IP头中所指示的长度 */
	if (!pskb_may_pull(skb, iph->ihl*4))
		goto inhdr_error;

	/* pskb_may_pull()中很可能会改变IP头指针的位置，重新取下IP头指针 */
	iph = ip_hdr(skb);

	/* IP头校验和检查 */
	if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl)))
		goto csum_error;

	/* IP数据总长度检查 */
	len = ntohs(iph->tot_len);
	if (skb->len < len) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INTRUNCATEDPKTS);
		goto drop;
	} else if (len < (iph->ihl*4))
		goto inhdr_error;

	/* Our transport medium may have padded the buffer out. Now we know it
	 * is IP we can trim to the true length of the frame.
	 * Note this now means skb->len holds ntohs(iph->tot_len).
	 */
	/* 去掉尾部可能多余的部分，只取IP真正需要的数据即可
	   例如以太网负载最小46字节，IP数据可能并没有那么长
	   但是以太网发送帧前需要补足，附加的pad数据就不是IP需要关心的数据了 */
	if (pskb_trim_rcsum(skb, len)) {
		IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INDISCARDS);
		goto drop;
	}

	/* Remove any debris in the socket control block */
	/* debris:碎片
	   cb[]字段在前面的处理中可能被使用过，这里清0 */
	memset(IPCB(skb), 0, sizeof(struct inet_skb_parm));

	/* Must drop socket now because of tproxy. */
	/* tproxy:透明(transparence)代理
	   使此skb脱离socket */
	skb_orphan(skb);

	/* ip_sabotage_in() NF_IP_PRI_FIRST
	   ipv4_conntrack_defrag() NF_IP_PRI_CONNTRACK_DEFRAG
	   ipv4_conntrack_in() NF_IP_PRI_CONNTRACK
	   nf_nat_in() NF_IP_PRI_NAT_DST */
	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING, skb, dev, NULL,
		       ip_rcv_finish);

csum_error:
	IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_CSUMERRORS);
inhdr_error:
	IP_INC_STATS_BH(dev_net(dev), IPSTATS_MIB_INHDRERRORS);
drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;
}

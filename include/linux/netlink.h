#ifndef __LINUX_NETLINK_H
#define __LINUX_NETLINK_H

#include <linux/socket.h> /* for __kernel_sa_family_t */
#include <linux/types.h>

/*
协议族PF_NETLINK的子协议
对应理解为全局变量nl_table的下标

如果按照PF_INET协议来理解，这里的子协议相当于IPPROTO_TCP IPPROTO_UDP
*/
/* 路由daemon */
#define NETLINK_ROUTE		0	/* Routing/device hook				*/
#define NETLINK_UNUSED		1	/* Unused number				*/
/* 用户态socket协议 */
#define NETLINK_USERSOCK	2	/* Reserved for user mode socket protocols 	*/
/* 防火墙 */
#define NETLINK_FIREWALL	3	/* Unused number, formerly ip_queue		*/
/* socket监视 */
#define NETLINK_SOCK_DIAG	4	/* socket monitoring				*/
/* netfilter日志 */
#define NETLINK_NFLOG		5	/* netfilter/iptables ULOG */
/* ipsec安全策略 */
#define NETLINK_XFRM		6	/* ipsec */
/* SELinux事件通知 */
#define NETLINK_SELINUX		7	/* SELinux event notifications */
/* iSCSI子系统 */
#define NETLINK_ISCSI		8	/* Open-iSCSI */
/* 进程审计 */
#define NETLINK_AUDIT		9	/* auditing */
/* 转发信息表查询 */
#define NETLINK_FIB_LOOKUP	10	
#define NETLINK_CONNECTOR	11
/* netfilter子系统 */
#define NETLINK_NETFILTER	12	/* netfilter subsystem */
/* IPv6防火墙 */
#define NETLINK_IP6_FW		13
/* DECnet路由信息 */
#define NETLINK_DNRTMSG		14	/* DECnet routing messages */
/* 内核事件向用户态通知 */
#define NETLINK_KOBJECT_UEVENT	15	/* Kernel messages to userspace */
/* 通用netlink */
#define NETLINK_GENERIC		16
/* leave room for NETLINK_DM (DM Events) */
#define NETLINK_SCSITRANSPORT	18	/* SCSI Transports */
#define NETLINK_ECRYPTFS	19
#define NETLINK_RDMA		20
#define NETLINK_CRYPTO		21	/* Crypto layer */

#define NETLINK_INET_DIAG	NETLINK_SOCK_DIAG

#define MAX_LINKS 32		

struct sockaddr_nl {
	/* 协议族AF_NETLINK */
	__kernel_sa_family_t	nl_family;	/* AF_NETLINK	*/
	unsigned short	nl_pad;		/* zero		*/
	/* 如果nl_pid设置为0，表示消息接收者为内核或多播组 */
	__u32		nl_pid;		/* port ID	*/
	/* 如果nl_groups设置为0，表示该消息为单播消息，否则表示多播消息 */
       	__u32		nl_groups;	/* multicast groups mask */
};

/*
每一个发送给内核或者从内核接收的报文都有一个相同的报文头，
这个报文头的结构如下定义
*/
struct nlmsghdr {
	/* 消息总长度，包括数据部分长度和该结构大小 */
	__u32		nlmsg_len;	/* Length of message including header */
	/* 消息类型 */
	__u16		nlmsg_type;	/* Message content */
	/* 消息标志 */
	__u16		nlmsg_flags;	/* Additional flags */
	__u32		nlmsg_seq;	/* Sequence number */
	__u32		nlmsg_pid;	/* Sending process port ID */
};

/* Flags values */

/* 表示消息是一个请求，所有应用首先发起的消息都应设置该标志 */
#define NLM_F_REQUEST		1	/* It is request message. 	*/
/* 用于指示该消息是一个多部分消息的一部分，后续的消息可以通过宏NLMSG_NEXT来获得 */
#define NLM_F_MULTI		2	/* Multipart message, terminated by NLMSG_DONE */
/* 表示该消息是前一个请求消息的响应
序列号与端口id可以把请求与响应关联起来
*/
#define NLM_F_ACK		4	/* Reply with ack, with zero or error code */
/* 表示该消息是相关的一个包的回传 */
#define NLM_F_ECHO		8	/* Echo this request 		*/
#define NLM_F_DUMP_INTR		16	/* Dump was inconsistent due to sequence change */

/* Modifiers to GET request */
/* 标志NLM_F_ROOT 被许多 netlink 协议的各种数据获取操作使用，
该标志指示被请求的数据表应当整体返回用户应用，而不是一个条目一个条目地返回。
有该标志的请求通常导致响应消息设置 NLM_F_MULTI标志。
注意，当设置了该标志时，请求是协议特定的，因此，需要在字段 nlmsg_type 中指定协议类型。
*/
#define NLM_F_ROOT	0x100	/* specify tree	root	*/
/* 标志 NLM_F_MATCH 表示该协议特定的请求只需要一个数据子集，
数据子集由指定的协议特定的过滤器来匹配。
*/
#define NLM_F_MATCH	0x200	/* return all matching	*/
/* 标志 NLM_F_ATOMIC 指示请求返回的数据应当原子地收集，
这预防数据在获取期间被修改。
*/
#define NLM_F_ATOMIC	0x400	/* atomic GET		*/
#define NLM_F_DUMP	(NLM_F_ROOT|NLM_F_MATCH)

/* Modifiers to NEW request */
/* 标志 NLM_F_REPLACE 用于取代在数据表中的现有条目。 */
#define NLM_F_REPLACE	0x100	/* Override existing		*/
/* 标志 NLM_F_EXCL_ 用于和 CREATE 和 APPEND 配合使用，如果条目已经存在，将失败。 */
#define NLM_F_EXCL	0x200	/* Do not touch, if it exists	*/
/* 标志 NLM_F_CREATE 指示应当在指定的表中创建一个条目。 */
#define NLM_F_CREATE	0x400	/* Create, if it does not exist	*/
/* 标志 NLM_F_APPEND 指示在表末尾添加新的条目。 */
#define NLM_F_APPEND	0x800	/* Add to end of list		*/

/*
   4.4BSD ADD		NLM_F_CREATE|NLM_F_EXCL
   4.4BSD CHANGE	NLM_F_REPLACE

   True CHANGE		NLM_F_CREATE|NLM_F_REPLACE
   Append		NLM_F_CREATE
   Check		NLM_F_EXCL
 */

/* 对齐到4字节 */
#define NLMSG_ALIGNTO	4U
/* @len按NLMSG_ALIGNTO对齐 */
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
/* 消息头长度 */
#define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
/* 消息总长度，包括数据@len和消息头 */
#define NLMSG_LENGTH(len) ((len)+NLMSG_ALIGN(NLMSG_HDRLEN))
/* @len长度的数据加上消息头对齐后占用的空间大小 */
#define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
/* netlink消息体的payload指针 */
#define NLMSG_DATA(nlh)  ((void*)(((char*)nlh) + NLMSG_LENGTH(0)))
/* 从多个netlink消息中取下一部分
@nlh	: nlmsghdr头指针
@len	: 可以使用的数据的长度

@len减去前一个@nlh的长度
得到下一个nlmsghdr的指针
*/
#define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
				  (struct nlmsghdr*)(((char*)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))
/* @len长度的数据中
还可能存在有效的netlink消息
*/
#define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
			   (nlh)->nlmsg_len <= (len))
/* 消息的负载数据长度
@len取0的话，则指去掉nlmsghdr后数据的长度
取其他值，则表示另外再去掉数据中@len长的自定义头后余下的负载长度
*/
#define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))

#define NLMSG_NOOP		0x1	/* Nothing.		*/
#define NLMSG_ERROR		0x2	/* Error		*/
#define NLMSG_DONE		0x3	/* End of a dump	*/
#define NLMSG_OVERRUN		0x4	/* Data lost		*/

#define NLMSG_MIN_TYPE		0x10	/* < 0x10: reserved control messages */

struct nlmsgerr {
	int		error;
	struct nlmsghdr msg;
};

#define NETLINK_ADD_MEMBERSHIP	1
#define NETLINK_DROP_MEMBERSHIP	2
#define NETLINK_PKTINFO		3
#define NETLINK_BROADCAST_ERROR	4
#define NETLINK_NO_ENOBUFS	5

struct nl_pktinfo {
	__u32	group;
};

#define NET_MAJOR 36		/* Major 36 is reserved for networking 						*/

enum {
	NETLINK_UNCONNECTED = 0,
	NETLINK_CONNECTED,
};

/*
 *  <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 * |        Header       | Pad |     Payload       | Pad |
 * |   (struct nlattr)   | ing |                   | ing |
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 *  <-------------- nlattr->nla_len -------------->
 */

struct nlattr {
	__u16           nla_len;
	__u16           nla_type;
};

/*
 * nla_type (16 bits)
 * +---+---+-------------------------------+
 * | N | O | Attribute Type                |
 * +---+---+-------------------------------+
 * N := Carries nested attributes
 * O := Payload stored in network byte order
 *
 * Note: The N and O flag are mutually exclusive.
 */
#define NLA_F_NESTED		(1 << 15)
#define NLA_F_NET_BYTEORDER	(1 << 14)
#define NLA_TYPE_MASK		~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

#define NLA_ALIGNTO		4
#define NLA_ALIGN(len)		(((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN		((int) NLA_ALIGN(sizeof(struct nlattr)))

#ifdef __KERNEL__

#include <linux/capability.h>
#include <linux/skbuff.h>

struct net;

/* 从data数据取nlmsghdr指针 */
static inline struct nlmsghdr *nlmsg_hdr(const struct sk_buff *skb)
{
	return (struct nlmsghdr *)skb->data;
}

/* 在skb的cb[]字段中保存的netlink参数 */
struct netlink_skb_parms {
	struct ucred		creds;		/* Skb credentials	*/
	__u32			pid;
	__u32			dst_group;
};

#define NETLINK_CB(skb)		(*(struct netlink_skb_parms*)&((skb)->cb))
#define NETLINK_CREDS(skb)	(&NETLINK_CB((skb)).creds)


extern void netlink_table_grab(void);
extern void netlink_table_ungrab(void);

/* optional Netlink kernel configuration parameters */
struct netlink_kernel_cfg {
	unsigned int	groups;
	void		(*input)(struct sk_buff *skb);
	struct mutex	*cb_mutex;
	void		(*bind)(int group);
};

extern struct sock *netlink_kernel_create(struct net *net, int unit,
					  struct module *module,
					  struct netlink_kernel_cfg *cfg);
extern void netlink_kernel_release(struct sock *sk);
extern int __netlink_change_ngroups(struct sock *sk, unsigned int groups);
extern int netlink_change_ngroups(struct sock *sk, unsigned int groups);
extern void __netlink_clear_multicast_users(struct sock *sk, unsigned int group);
extern void netlink_clear_multicast_users(struct sock *sk, unsigned int group);
extern void netlink_ack(struct sk_buff *in_skb, struct nlmsghdr *nlh, int err);
extern int netlink_has_listeners(struct sock *sk, unsigned int group);
extern int netlink_unicast(struct sock *ssk, struct sk_buff *skb, __u32 pid, int nonblock);
extern int netlink_broadcast(struct sock *ssk, struct sk_buff *skb, __u32 pid,
			     __u32 group, gfp_t allocation);
extern int netlink_broadcast_filtered(struct sock *ssk, struct sk_buff *skb,
	__u32 pid, __u32 group, gfp_t allocation,
	int (*filter)(struct sock *dsk, struct sk_buff *skb, void *data),
	void *filter_data);
extern int netlink_set_err(struct sock *ssk, __u32 pid, __u32 group, int code);
extern int netlink_register_notifier(struct notifier_block *nb);
extern int netlink_unregister_notifier(struct notifier_block *nb);

/* finegrained unicast helpers: */
struct sock *netlink_getsockbyfilp(struct file *filp);
int netlink_attachskb(struct sock *sk, struct sk_buff *skb,
		      long *timeo, struct sock *ssk);
void netlink_detachskb(struct sock *sk, struct sk_buff *skb);
int netlink_sendskb(struct sock *sk, struct sk_buff *skb);

/*
 *	skb should fit one page. This choice is good for headerless malloc.
 *	But we should limit to 8K so that userspace does not have to
 *	use enormous buffer sizes on recvmsg() calls just to avoid
 *	MSG_TRUNC when PAGE_SIZE is very large.
 */
/* 控制在一页内
数据区大小
*/
#if PAGE_SIZE < 8192UL
#define NLMSG_GOODSIZE	SKB_WITH_OVERHEAD(PAGE_SIZE)
#else
#define NLMSG_GOODSIZE	SKB_WITH_OVERHEAD(8192UL)
#endif

/* 除去nlmsghdr消息头的数据大小 */
#define NLMSG_DEFAULT_SIZE (NLMSG_GOODSIZE - NLMSG_HDRLEN)


struct netlink_callback {
	struct sk_buff		*skb;
	const struct nlmsghdr	*nlh;
	int			(*dump)(struct sk_buff * skb,
					struct netlink_callback *cb);
	int			(*done)(struct netlink_callback *cb);
	void			*data;
	u16			family;
	u16			min_dump_alloc;
	unsigned int		prev_seq, seq;
	long			args[6];
};

struct netlink_notify {
	struct net *net;
	int pid;
	int protocol;
};

struct nlmsghdr *
__nlmsg_put(struct sk_buff *skb, u32 pid, u32 seq, int type, int len, int flags);

struct netlink_dump_control {
	int (*dump)(struct sk_buff *skb, struct netlink_callback *);
	int (*done)(struct netlink_callback*);
	void *data;
	u16 min_dump_alloc;
};

extern int netlink_dump_start(struct sock *ssk, struct sk_buff *skb,
			      const struct nlmsghdr *nlh,
			      struct netlink_dump_control *control);


#define NL_NONROOT_RECV 0x1
#define NL_NONROOT_SEND 0x2
extern void netlink_set_nonroot(int protocol, unsigned flag);

#endif /* __KERNEL__ */

#endif	/* __LINUX_NETLINK_H */

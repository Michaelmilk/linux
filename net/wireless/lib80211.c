/*
 * lib80211 -- common bits for IEEE802.11 drivers
 *
 * Copyright(c) 2008 John W. Linville <linville@tuxdriver.com>
 *
 * Portions copied from old ieee80211 component, w/ original copyright
 * notices below:
 *
 * Host AP crypto routines
 *
 * Copyright (c) 2002-2003, Jouni Malinen <j@w1.fi>
 * Portions Copyright (C) 2004, Intel Corporation <jketreno@linux.intel.com>
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/ieee80211.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <net/lib80211.h>

#define DRV_NAME        "lib80211"

#define DRV_DESCRIPTION	"common routines for IEEE802.11 drivers"

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR("John W. Linville <linville@tuxdriver.com>");
MODULE_LICENSE("GPL");

struct lib80211_crypto_alg {
	/* 通过list字段加入lib80211_crypto_algs链表 */
	struct list_head list;
	struct lib80211_crypto_ops *ops;
};

/* 加密算法操作函数链表头 */
static LIST_HEAD(lib80211_crypto_algs);
/* 自旋锁控制链表的并发 */
static DEFINE_SPINLOCK(lib80211_crypto_lock);

static void lib80211_crypt_deinit_entries(struct lib80211_crypt_info *info,
					  int force);
static void lib80211_crypt_quiescing(struct lib80211_crypt_info *info);
static void lib80211_crypt_deinit_handler(unsigned long data);

const char *print_ssid(char *buf, const char *ssid, u8 ssid_len)
{
	/* 源 */
	const char *s = ssid;
	/* 目的 */
	char *d = buf;

	/* 不能超过ssid的最大长度 */
	ssid_len = min_t(u8, ssid_len, IEEE80211_MAX_SSID_LEN);
	while (ssid_len--) {
		/* 可打印字符 */
		if (isprint(*s)) {
			*d++ = *s++;
			continue;
		}

		/* 反斜杠 */
		*d++ = '\\';
		if (*s == '\0')
			*d++ = '0';
		else if (*s == '\n')
			*d++ = 'n';
		else if (*s == '\r')
			*d++ = 'r';
		else if (*s == '\t')
			*d++ = 't';
		else if (*s == '\\')
			*d++ = '\\';
		else
			d += snprintf(d, 3, "%03o", *s);
		s++;
	}
	/* 字符串结束符 */
	*d = '\0';
	return buf;
}
EXPORT_SYMBOL(print_ssid);

/*
初始化一个@info结构实例
*/
int lib80211_crypt_info_init(struct lib80211_crypt_info *info, char *name,
				spinlock_t *lock)
{
	/* 清0 */
	memset(info, 0, sizeof(*info));

	/* 名称 */
	info->name = name;
	/* 自旋锁 */
	info->lock = lock;

	/* 初始化链表头 */
	INIT_LIST_HEAD(&info->crypt_deinit_list);
	/* 设置定时器并初始化 */
	setup_timer(&info->crypt_deinit_timer, lib80211_crypt_deinit_handler,
			(unsigned long)info);

	return 0;
}
EXPORT_SYMBOL(lib80211_crypt_info_init);

void lib80211_crypt_info_free(struct lib80211_crypt_info *info)
{
	int i;

	/* @info进入静默期
	   lib80211_crypt_deinit_handler()中不会再次触发定时器
	*/
        lib80211_crypt_quiescing(info);
	/* 删除定时器 */
        del_timer_sync(&info->crypt_deinit_timer);
	/* 强制删除crypt_deinit_list链表下的lib80211_crypt_data */
        lib80211_crypt_deinit_entries(info, 1);

	/* 遍历crypt数组 */
        for (i = 0; i < NUM_WEP_KEYS; i++) {
                struct lib80211_crypt_data *crypt = info->crypt[i];
                if (crypt) {
                        if (crypt->ops) {
				/* 调用deinit函数 */
                                crypt->ops->deinit(crypt->priv);
                                module_put(crypt->ops->owner);
                        }
			/* 释放lib80211_crypt_data */
                        kfree(crypt);
                        info->crypt[i] = NULL;
                }
        }
}
EXPORT_SYMBOL(lib80211_crypt_info_free);

/*
删除crypt_deinit_list链表中的元素

@force	: 是否强制删除
*/
static void lib80211_crypt_deinit_entries(struct lib80211_crypt_info *info,
					  int force)
{
	struct lib80211_crypt_data *entry, *next;
	unsigned long flags;

	spin_lock_irqsave(info->lock, flags);
	/* 遍历deinit链表 */
	list_for_each_entry_safe(entry, next, &info->crypt_deinit_list, list) {
		/* 还有引用计数
		   并且不是强制删除
		   则先跳过
		*/
		if (atomic_read(&entry->refcnt) != 0 && !force)
			continue;

		/* 从链表中移出 */
		list_del(&entry->list);

		/* 有操作函数 */
		if (entry->ops) {
			/* 调用deinit函数 */
			entry->ops->deinit(entry->priv);
			/* 释放模块引用计数 */
			module_put(entry->ops->owner);
		}
		/* 释放lib80211_crypt_data结构实例 */
		kfree(entry);
	}
	spin_unlock_irqrestore(info->lock, flags);
}

/* After this, crypt_deinit_list won't accept new members */
static void lib80211_crypt_quiescing(struct lib80211_crypt_info *info)
{
	unsigned long flags;

	spin_lock_irqsave(info->lock, flags);
	info->crypt_quiesced = 1;
	spin_unlock_irqrestore(info->lock, flags);
}

/*
定时器回调函数
*/
static void lib80211_crypt_deinit_handler(unsigned long data)
{
	struct lib80211_crypt_info *info = (struct lib80211_crypt_info *)data;
	unsigned long flags;

	/* 不强制删除 */
	lib80211_crypt_deinit_entries(info, 0);

	spin_lock_irqsave(info->lock, flags);
	/* 链表还没有清空
	   并且@info没有进入静默期
	   则触发定时器，延迟1秒继续处理
	*/
	if (!list_empty(&info->crypt_deinit_list) && !info->crypt_quiesced) {
		printk(KERN_DEBUG "%s: entries remaining in delayed crypt "
		       "deletion list\n", info->name);
		info->crypt_deinit_timer.expires = jiffies + HZ;
		add_timer(&info->crypt_deinit_timer);
	}
	spin_unlock_irqrestore(info->lock, flags);
}

/*
通过定时器延迟处理
*/
void lib80211_crypt_delayed_deinit(struct lib80211_crypt_info *info,
				    struct lib80211_crypt_data **crypt)
{
	struct lib80211_crypt_data *tmp;
	unsigned long flags;

	if (*crypt == NULL)
		return;

	tmp = *crypt;
	*crypt = NULL;

	/* must not run ops->deinit() while there may be pending encrypt or
	 * decrypt operations. Use a list of delayed deinits to avoid needing
	 * locking. */

	spin_lock_irqsave(info->lock, flags);
	/* 没有进入静默期 */
	if (!info->crypt_quiesced) {
		/* 加入crypt_deinit_list链表 */
		list_add(&tmp->list, &info->crypt_deinit_list);
		/* 定时器还没有激活 */
		if (!timer_pending(&info->crypt_deinit_timer)) {
			/* 设置定时器到期时间 */
			info->crypt_deinit_timer.expires = jiffies + HZ;
			/* 激活定时器 */
			add_timer(&info->crypt_deinit_timer);
		}
	}
	spin_unlock_irqrestore(info->lock, flags);
}
EXPORT_SYMBOL(lib80211_crypt_delayed_deinit);

/*
注册加密算法@ops
通过结构lib80211_crypto_alg将@ops加入lib80211_crypto_algs链表
*/
int lib80211_register_crypto_ops(struct lib80211_crypto_ops *ops)
{
	unsigned long flags;
	struct lib80211_crypto_alg *alg;

	/* 分配一个lib80211_crypto_alg结构实例 */
	alg = kzalloc(sizeof(*alg), GFP_KERNEL);
	if (alg == NULL)
		return -ENOMEM;

	/* 记录操作函数表 */
	alg->ops = ops;

	spin_lock_irqsave(&lib80211_crypto_lock, flags);
	/* 通过list字段加入lib80211_crypto_algs链表 */
	list_add(&alg->list, &lib80211_crypto_algs);
	spin_unlock_irqrestore(&lib80211_crypto_lock, flags);

	printk(KERN_DEBUG "lib80211_crypt: registered algorithm '%s'\n",
	       ops->name);

	return 0;
}
EXPORT_SYMBOL(lib80211_register_crypto_ops);

/*
将@ops从链表中移出
*/
int lib80211_unregister_crypto_ops(struct lib80211_crypto_ops *ops)
{
	struct lib80211_crypto_alg *alg;
	unsigned long flags;

	spin_lock_irqsave(&lib80211_crypto_lock, flags);
	/* 遍历lib80211_crypto_algs链表 */
	list_for_each_entry(alg, &lib80211_crypto_algs, list) {
		/* 找到 */
		if (alg->ops == ops)
			goto found;
	}
	spin_unlock_irqrestore(&lib80211_crypto_lock, flags);
	return -EINVAL;

      found:
	printk(KERN_DEBUG "lib80211_crypt: unregistered algorithm '%s'\n",
	       ops->name);
	/* 移出链表 */
	list_del(&alg->list);
	spin_unlock_irqrestore(&lib80211_crypto_lock, flags);
	/* 释放注册时申请的lib80211_crypto_alg结构实例 */
	kfree(alg);
	return 0;
}
EXPORT_SYMBOL(lib80211_unregister_crypto_ops);

/*
根据算法名称查找加密算法操作函数
*/
struct lib80211_crypto_ops *lib80211_get_crypto_ops(const char *name)
{
	struct lib80211_crypto_alg *alg;
	unsigned long flags;

	spin_lock_irqsave(&lib80211_crypto_lock, flags);
	/* 遍历lib80211_crypto_algs链表 */
	list_for_each_entry(alg, &lib80211_crypto_algs, list) {
		/* 名称一致 */
		if (strcmp(alg->ops->name, name) == 0)
			goto found;
	}
	spin_unlock_irqrestore(&lib80211_crypto_lock, flags);
	return NULL;

      found:
	spin_unlock_irqrestore(&lib80211_crypto_lock, flags);
	/* 找到，返回加密算法操作函数表 */
	return alg->ops;
}
EXPORT_SYMBOL(lib80211_get_crypto_ops);

static void *lib80211_crypt_null_init(int keyidx)
{
	return (void *)1;
}

static void lib80211_crypt_null_deinit(void *priv)
{
}

static struct lib80211_crypto_ops lib80211_crypt_null = {
	.name = "NULL",
	.init = lib80211_crypt_null_init,
	.deinit = lib80211_crypt_null_deinit,
	.owner = THIS_MODULE,
};

static int __init lib80211_init(void)
{
	pr_info(DRV_DESCRIPTION "\n");
	/* 注册一个null算法 */
	return lib80211_register_crypto_ops(&lib80211_crypt_null);
}

static void __exit lib80211_exit(void)
{
	/* 移出null算法 */
	lib80211_unregister_crypto_ops(&lib80211_crypt_null);
	/* 模块卸载的时候
	   lib80211_crypto_algs链表应该为空
	*/
	BUG_ON(!list_empty(&lib80211_crypto_algs));
}

module_init(lib80211_init);
module_exit(lib80211_exit);

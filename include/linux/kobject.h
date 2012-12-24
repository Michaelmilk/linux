/*
 * kobject.h - generic kernel object infrastructure.
 *
 * Copyright (c) 2002-2003 Patrick Mochel
 * Copyright (c) 2002-2003 Open Source Development Labs
 * Copyright (c) 2006-2008 Greg Kroah-Hartman <greg@kroah.com>
 * Copyright (c) 2006-2008 Novell Inc.
 *
 * This file is released under the GPLv2.
 *
 * Please read Documentation/kobject.txt before using the kobject
 * interface, ESPECIALLY the parts about reference counts and object
 * destructors.
 */

#ifndef _KOBJECT_H_
#define _KOBJECT_H_

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sysfs.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <linux/kobject_ns.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <linux/atomic.h>

#define UEVENT_HELPER_PATH_LEN		256
#define UEVENT_NUM_ENVP			32	/* number of env pointers */
#define UEVENT_BUFFER_SIZE		2048	/* buffer for the variables */

/* path to the userspace helper executed on an event */
extern char uevent_helper[];

/* counter to tag the uevent, read only except for the kobject core */
extern u64 uevent_seqnum;

/*
 * The actions here must match the index to the string array
 * in lib/kobject_uevent.c
 *
 * Do not add new actions here without checking with the driver-core
 * maintainers. Action strings are not meant to express subsystem
 * or device specific properties. In most cases you want to send a
 * kobject_uevent_env(kobj, KOBJ_CHANGE, env) with additional event
 * specific variables added to the event environment.
 */
enum kobject_action {
	KOBJ_ADD,
	KOBJ_REMOVE,
	KOBJ_CHANGE,
	KOBJ_MOVE,
	KOBJ_ONLINE,
	KOBJ_OFFLINE,
	KOBJ_MAX
};

/*
kobjectͨ����Ƕ�뵽�����ṹ�еģ��䵥��������ʵ������
�෴����Щ��Ϊ��Ҫ�Ľṹ���������Ҫ�õ�kobject�ṹ������struct cdev��

��kobject��Ƕ�뵽�����ṹ����ʱ���ýṹ���ӵ����kobject�ṩ�ı�׼���ܡ�
����Ҫ��һ���ǣ�Ƕ��kobject�ṹ����Գ�Ϊ�����μܹ��е�һ���֡�
����cdev�ṹ��Ϳ���ͨ���丸����ָ��cdev->kobj->parent
������cdev->kobj->entry�����뵽�����νṹ�С�

kobject�����豸����ģ����һ���������������� MFC �����Ļ��� CObject��
ÿ��kobject����Ӧ��sysfs�е�һ��Ŀ¼��
�ϲ�ṹ���� device,device_driver,bus_type��Ƕ����һ�� kobject��
���൱��������������������еļ̳л���
*/
struct kobject {
	/* kobject���� */
	const char		*name;
	/* ������������kset��list���� */
	struct list_head	entry;
	/* parentָ��ָ��kobject�ĸ�����
       ��ˣ�kobject�ͻ����ں��й���һ�������νṹ��
       ���ҿ��Խ��Ը������Ĺ�ϵ���ֳ����������㿴���ģ�
       �����sysfs��������Ŀ��һ���û��ռ���ļ�ϵͳ��
       ������ʾ�ں���kobject����Ĳ�νṹ��

       ĳ�����kobj->parentָ������kobj->kset->kobjӦ����һ�µ�
       kobject_add_internal()�����ڸ�ֵ */
	struct kobject		*parent;
	/* ����kset������ʵ�ֲ�� */
	struct kset		*kset;
	/* ����ktype��ָ���������� */
	struct kobj_type	*ktype;
	/* sysfs�е�Ŀ¼�����sysfs_create_dir()�ڸ�ֵ */
	struct sysfs_dirent	*sd;
	/* ���ü���
	   ������Ƕ��kobject�ṹ�������ṹ�����ü���Ҳ�ɴ��ֶ�����¼ */
	struct kref		kref;
	unsigned int state_initialized:1;
	unsigned int state_in_sysfs:1;
	unsigned int state_add_uevent_sent:1;
	unsigned int state_remove_uevent_sent:1;
	unsigned int uevent_suppress:1;
};

extern __printf(2, 3)
int kobject_set_name(struct kobject *kobj, const char *name, ...);
extern int kobject_set_name_vargs(struct kobject *kobj, const char *fmt,
				  va_list vargs);

static inline const char *kobject_name(const struct kobject *kobj)
{
	return kobj->name;
}

extern void kobject_init(struct kobject *kobj, struct kobj_type *ktype);
extern __printf(3, 4) __must_check
int kobject_add(struct kobject *kobj, struct kobject *parent,
		const char *fmt, ...);
extern __printf(4, 5) __must_check
int kobject_init_and_add(struct kobject *kobj,
			 struct kobj_type *ktype, struct kobject *parent,
			 const char *fmt, ...);

extern void kobject_del(struct kobject *kobj);

extern struct kobject * __must_check kobject_create(void);
extern struct kobject * __must_check kobject_create_and_add(const char *name,
						struct kobject *parent);

extern int __must_check kobject_rename(struct kobject *, const char *new_name);
extern int __must_check kobject_move(struct kobject *, struct kobject *);

extern struct kobject *kobject_get(struct kobject *kobj);
extern void kobject_put(struct kobject *kobj);

extern char *kobject_get_path(struct kobject *kobj, gfp_t flag);

/*
kobj_type��Ϊ������һ��kobject�����е��ձ����ԡ�
��ˣ�������Ҫÿ��kobject���ֱ����Լ������ԣ�
���ǽ���Щ�ձ��������kobj_type�ṹ����һ�ζ��壬
Ȼ�����С�ͬ�ࡱ��kobject���ܹ���һ�������ԡ�

releaseָ��ָ����kobject���ü�������0ʱҪ�����õ�����������
�ú��������ͷ�����kobjectʹ�õ��ڴ�����������������

sysfs_ops����ָ��sysfs_ops�ṹ�塣�ýṹ��������sysfs�ļ���дʱ�����ԡ�

default_attrsָ��һ��attribute�ṹ�����顣
��Щ�ṹ�嶨���˸�kobject��ص�Ĭ�����ԡ�
���Ը����˶���������������kobject��������sysfs�У�
��ô��Щ���Զ�����Ӧ����Ϊ�ļ���������

kobj_type��kobject���������ͣ�������ĳ�����͵�kobejct�Ĺ��������ԺͲ���
*/
struct kobj_type {
	void (*release)(struct kobject *kobj);
	const struct sysfs_ops *sysfs_ops;
	struct attribute **default_attrs;
	const struct kobj_ns_type_operations *(*child_ns_type)(struct kobject *kobj);
	const void *(*namespace)(struct kobject *kobj);
};

struct kobj_uevent_env {
	char *envp[UEVENT_NUM_ENVP];
	int envp_idx;
	char buf[UEVENT_BUFFER_SIZE];
	int buflen;
};

struct kset_uevent_ops {
	int (* const filter)(struct kset *kset, struct kobject *kobj);
	const char *(* const name)(struct kset *kset, struct kobject *kobj);
	int (* const uevent)(struct kset *kset, struct kobject *kobj,
		      struct kobj_uevent_env *env);
};

struct kobj_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf);
	ssize_t (*store)(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count);
};

extern const struct sysfs_ops kobj_sysfs_ops;

struct sock;

/**
 * struct kset - a set of kobjects of a specific type, belonging to a specific subsystem.
 *
 * A kset defines a group of kobjects.  They can be individually
 * different "types" but overall these kobjects all want to be grouped
 * together and operated on in the same manner.  ksets are used to
 * define the attribute callbacks and other common events that happen to
 * a kobject.
 *
 * @list: the list of all kobjects for this kset
 * @list_lock: a lock for iterating over the kobjects
 * @kobj: the embedded kobject for this kset (recursion, isn't it fun...)
 * @uevent_ops: the set of uevent operations for this kset.  These are
 * called whenever a kobject has something happen to it so that the kset
 * can add new environment variables, or filter out the uevents if so
 * desired.
 */
/*
kset��kobject����ļ����塣
��������һ���������ɽ�������ص�kobject����
���硰ȫ���Ŀ��豸������ͬһλ�á�
kset��kobject���е�һ��������
kobject��ksetָ��ָ����Ӧ��kset���ϡ�

kset ��һ��kobject ���ϣ��������� ��������һϵ�е� kobject��
��Ҫע����ǣ�kset�ڲ�ҲǶ���� kobject������� kset ����Ҳ��һ�� kobject��

Kset �ڸ�������һ�����ϻ��߽�������
ʵ���˶���Ĳ�Ρ�
��������һ��ksets�Ķ���(kobject)��parent��ָ���ksets��kobj
ͬʱ����������ӵ�kset ��list���ϡ�
ͬʱλ��ksets���֮�ϵ���subsys�������µ��ں����Ѿ�ȡ��subsys��
��Ϊ��������Ҳ����һ��ksets��
Kset��һ������kobject�Ĳ�����ʵ����ֻ�ǽ�һ������������kobj����Ӧ������
�Ͼ�ksets������Ҳ��һ��kobject��

kobjectͨ��kset��֯�ɲ�λ��Ľṹ��kset�Ǿ�����ͬ���͵�kobject�ļ���
*/
struct kset {
	/* ���Ӹü���(kset)�����е�kobject����
	   ��kobject.entry�����listΪ��ͷ������ */
	struct list_head list;
	spinlock_t list_lock;
	/* kobjָ���kobject��������˸ü��ϵĻ��� */
	struct kobject kobj;
	/* �Ȳ�β��� */
	const struct kset_uevent_ops *uevent_ops;
};

extern void kset_init(struct kset *kset);
extern int __must_check kset_register(struct kset *kset);
extern void kset_unregister(struct kset *kset);
extern struct kset * __must_check kset_create_and_add(const char *name,
						const struct kset_uevent_ops *u,
						struct kobject *parent_kobj);

static inline struct kset *to_kset(struct kobject *kobj)
{
	return kobj ? container_of(kobj, struct kset, kobj) : NULL;
}

/*
ʵ����������kset->kobj->kref�����ü���
*/
static inline struct kset *kset_get(struct kset *k)
{
	return k ? to_kset(kobject_get(&k->kobj)) : NULL;
}

static inline void kset_put(struct kset *k)
{
	kobject_put(&k->kobj);
}

static inline struct kobj_type *get_ktype(struct kobject *kobj)
{
	return kobj->ktype;
}

extern struct kobject *kset_find_obj(struct kset *, const char *);

/* The global /sys/kernel/ kobject for people to chain off of */
extern struct kobject *kernel_kobj;
/* The global /sys/kernel/mm/ kobject for people to chain off of */
extern struct kobject *mm_kobj;
/* The global /sys/hypervisor/ kobject for people to chain off of */
extern struct kobject *hypervisor_kobj;
/* The global /sys/power/ kobject for people to chain off of */
extern struct kobject *power_kobj;
/* The global /sys/firmware/ kobject for people to chain off of */
extern struct kobject *firmware_kobj;

int kobject_uevent(struct kobject *kobj, enum kobject_action action);
int kobject_uevent_env(struct kobject *kobj, enum kobject_action action,
			char *envp[]);

__printf(2, 3)
int add_uevent_var(struct kobj_uevent_env *env, const char *format, ...);

int kobject_action_type(const char *buf, size_t count,
			enum kobject_action *type);

#endif /* _KOBJECT_H_ */

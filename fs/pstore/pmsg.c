// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2014  Google, Inc.
 */

// pmsg 前端的实现

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/rtmutex.h>
#include "internal.h"

static DEFINE_RT_MUTEX(pmsg_lock);	// 定义一个实时互斥锁，用于控制对 pmsg 操作的并发访问

/*
 * 实现了写入用户空间数据到 pstore 的功能。通过使用一个互斥锁来确保操作的原子性，
 * 确保了在并发环境下数据的一致性和完整性。同时，通过检查用户提供的内存地址的有效性，提高了函数的健壮性。
 */
static ssize_t write_pmsg(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct pstore_record record;	// 定义一个 pstore 记录结构
	int ret;	// 用于存储返回值

	if (!count)	// 如果计数为0，则无需写入任何数据
		return 0;	// 直接返回0，表示成功但未写入任何数据

	pstore_record_init(&record, psinfo);	// 初始化 pstore 记录结构
	record.type = PSTORE_TYPE_PMSG;		// 设置记录类型为 PMSG
	record.size = count;			// 设置记录大小为调用者请求写入的字节数

	/* check outside lock, page in any data. write_user also checks */
	// 检查用户空间地址是否可访问
	if (!access_ok(buf, count))
		return -EFAULT;	// 如果用户空间地址不可访问，则返回错误

	// 锁定 pmsg 互斥锁以保证线程安全
	rt_mutex_lock(&pmsg_lock);
	ret = psinfo->write_user(&record, buf);	// 写入用户提供的数据到 pstore
	rt_mutex_unlock(&pmsg_lock);	// 解锁 pmsg 互斥锁
	return ret ? ret : count;	// 如果写入操作返回错误，则返回错误代码，否则返回写入的字节数
}

// 定义 pmsg 设备的文件操作结构体
static const struct file_operations pmsg_fops = {
	.owner		= THIS_MODULE,	// 指定模块拥有者
	.llseek		= noop_llseek,	// 禁用文件偏移操作，无操作llseek
	.write		= write_pmsg,	// 指定写操作为 write_pmsg 函数
};

static struct class *pmsg_class; // 定义设备类指针，用于设备和驱动的注册
static int pmsg_major; // 定义主设备号
#define PMSG_NAME "pmsg" // 定义设备名称为 "pmsg"
#undef pr_fmt // 取消之前可能存在的宏定义
#define pr_fmt(fmt) PMSG_NAME ": " fmt // 定义日志输出的格式前缀

// 定义设备节点的权限设置函数
static char *pmsg_devnode(struct device *dev, umode_t *mode)
{
	if (mode)	// 如果 mode 指针非空
		*mode = 0220;	// 设置设备文件权限为 0220，即用户写权限
	return NULL;	// 返回 NULL，不修改设备名称
}

void pstore_register_pmsg(void)
{
	struct device *pmsg_device;

	// 注册字符设备，获取动态分配的主设备号
	pmsg_major = register_chrdev(0, PMSG_NAME, &pmsg_fops);
	if (pmsg_major < 0) {	// 如果注册失败
		pr_err("register_chrdev failed\n");	// 打印错误信息
		goto err;	// 跳转到错误处理
	}

	// 创建设备类，用于后续创建设备文件
	pmsg_class = class_create(THIS_MODULE, PMSG_NAME);
	if (IS_ERR(pmsg_class)) {	// 检查设备类创建是否失败
		pr_err("device class file already in use\n");	// 打印设备类已被使用的错误信息
		goto err_class;	// 跳转到错误处理
	}
	pmsg_class->devnode = pmsg_devnode;	// 设置设备节点的权限设置函数

	// 创建设备文件
	pmsg_device = device_create(pmsg_class, NULL, MKDEV(pmsg_major, 0),
					NULL, "%s%d", PMSG_NAME, 0);
	if (IS_ERR(pmsg_device)) {	// 检查设备文件创建是否失败
		pr_err("failed to create device\n");	// 打印创建设备失败的错误信息
		goto err_device;	// 跳转到错误处理
	}
	return;

err_device:	// 设备文件创建失败的处理
	class_destroy(pmsg_class);	// 销毁之前创建的设备类
err_class:	// 设备类创建失败的处理
	unregister_chrdev(pmsg_major, PMSG_NAME);	// 注销之前注册的字符设备
err:	// 通用错误处理
	return;	// 结束函数
}

void pstore_unregister_pmsg(void)
{
	device_destroy(pmsg_class, MKDEV(pmsg_major, 0));	// 销毁设备文件
	class_destroy(pmsg_class);	 // 销毁设备类
	unregister_chrdev(pmsg_major, PMSG_NAME);	// 注销字符设备
}

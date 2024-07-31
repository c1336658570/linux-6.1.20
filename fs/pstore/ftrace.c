// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2012  Google, Inc.
 */


// ftrace前端实现

#include <linux/kernel.h>
#include <linux/compiler.h>
#include <linux/irqflags.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/ftrace.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/cache.h>
#include <linux/slab.h>
#include <asm/barrier.h>
#include "internal.h"

/* This doesn't need to be atomic: speed is chosen over correctness here. */
/* 这个操作不需要是原子的：这里选择速度优先而不是正确性 */
static u64 pstore_ftrace_stamp;

// 定义一个不会被追踪的函数，专门用来记录函数调用的ftrace数据
static void notrace pstore_ftrace_call(unsigned long ip,
				       unsigned long parent_ip,
				       struct ftrace_ops *op,
				       struct ftrace_regs *fregs)
{
	int bit;	// 用于记录是否成功获得递归锁
	unsigned long flags;	// 用于在禁用中断时保存状态
	/* 初始化记录结构，用于存储函数追踪信息 */
	struct pstore_ftrace_record rec = {};	// 初始化 ftrace 记录结构体
	/* 初始化 pstore 记录结构，设置记录类型为函数追踪 */
	struct pstore_record record = {	// 初始化 pstore 记录结构体，用于包装 ftrace 记录数据
		.type = PSTORE_TYPE_FTRACE,
		.buf = (char *)&rec,
		.size = sizeof(rec),
		.psi = psinfo,
	};

	/* 如果系统正在进行异常处理，则返回，不记录此信息 */
	if (unlikely(oops_in_progress))	// 如果系统正在处理内核崩溃，则直接返回，避免在崩溃时进行记录
		return;

	/* 尝试锁定递归保护，避免追踪函数递归调用自身 */
	bit = ftrace_test_recursion_trylock(ip, parent_ip);
	if (bit < 0)
		return;	// 如果获取递归锁失败，则直接返回

	/* 保存当前中断状态，并禁用本地中断 */
	local_irq_save(flags);

	// 填充 ftrace 记录的当前和父指令指针
	rec.ip = ip;
	rec.parent_ip = parent_ip;
	pstore_ftrace_write_timestamp(&rec, pstore_ftrace_stamp++);	// 写入时间戳
	pstore_ftrace_encode_cpu(&rec, raw_smp_processor_id());		// 编码并写入当前 CPU 信息
	psinfo->write(&record);	// 调用后端写入接口，将记录写入存储

	local_irq_restore(flags);	// 恢复之前的中断状态
	ftrace_test_recursion_unlock(bit);	// 解锁递归保护
}

// 定义一个静态的 ftrace 操作结构，初始化为只读最常用的状态，指定了 ftrace 记录函数
static struct ftrace_ops pstore_ftrace_ops __read_mostly = {
	.func	= pstore_ftrace_call,	// 设置回调函数为 pstore_ftrace_call
};

static DEFINE_MUTEX(pstore_ftrace_lock);	// 定义一个互斥锁，用于控制 pstore 的 ftrace 记录功能的启用状态
static bool pstore_ftrace_enabled;		// 定义一个布尔变量，标识当前 pstore 的 ftrace 记录功能是否已启用

// 定义一个函数，用于设置 pstore 的 ftrace 记录功能的启用状态
static int pstore_set_ftrace_enabled(bool on)
{
	ssize_t ret;	// 用于保存注册或注销 ftrace 函数的返回值

	// 如果当前状态已经与期望状态一致，则无需操作，直接返回
	if (on == pstore_ftrace_enabled)
		return 0;

	// 如果要求启用 ftrace 记录
	if (on) {
		ftrace_ops_set_global_filter(&pstore_ftrace_ops);	// 设置 ftrace 全局过滤器
		ret = register_ftrace_function(&pstore_ftrace_ops);	// 注册 ftrace 函数
	} else {
		ret = unregister_ftrace_function(&pstore_ftrace_ops);	// 注销 ftrace 函数
	}

	// 如果注册或注销操作返回错误
	if (ret) {
		// 打印错误信息，注明无法注册或注销 ftrace 操作
		pr_err("%s: unable to %sregister ftrace ops: %zd\n",
		       __func__, on ? "" : "un", ret);
	} else {
		pstore_ftrace_enabled = on;	// 操作成功时，更新 ftrace 记录功能的启用状态
	}

	return ret;	// 返回操作的结果
}

// 定义一个写操作的函数，用于处理来自用户空间的 ftrace 开启或关闭的请求
static ssize_t pstore_ftrace_knob_write(struct file *f, const char __user *buf,
					size_t count, loff_t *ppos)
{
	u8 on;	// 用来存储从用户空间读取的开关值
	ssize_t ret;	// 存储返回值

	// 尝试从用户空间读取一个字节并转换为无符号8位整数
	ret = kstrtou8_from_user(buf, count, 2, &on);
	if (ret)
		return ret;	// 如果读取或转换失败，返回错误

	mutex_lock(&pstore_ftrace_lock);	// 锁定 pstore_ftrace_lock 以确保设置操作的互斥
	ret = pstore_set_ftrace_enabled(on);	// 调用 pstore_set_ftrace_enabled 来设置 ftrace 的开启或关闭状态
	mutex_unlock(&pstore_ftrace_lock);	// 设置完毕后释放锁

	if (ret == 0)
		ret = count;	// 如果设置成功，返回写入的字节数，以表示操作成功完成

	return ret;	// 返回结果
}

// 定义一个读操作的函数，用于返回当前 ftrace 开启状态给用户空间
static ssize_t pstore_ftrace_knob_read(struct file *f, char __user *buf,
				       size_t count, loff_t *ppos)
{
	// 准备一个字符数组，表示 ftrace 的开启状态 ('1' 表示开启，'0' 表示关闭) 和换行符
	char val[] = { '0' + pstore_ftrace_enabled, '\n' };

	// 使用简单的缓冲区读取函数，将状态值返回给调用者
	return simple_read_from_buffer(buf, count, ppos, val, sizeof(val));
}

// 定义 pstore 的 file_operations 结构，包括打开、读和写操作
static const struct file_operations pstore_knob_fops = {
	.open	= simple_open,	// 使用简单的打开函数
	.read	= pstore_ftrace_knob_read,	// 读函数，用于获取 ftrace 开启状态
	.write	= pstore_ftrace_knob_write,	// 写函数，用于设置 ftrace 开启状态
};

// 定义指向 pstore ftrace 目录的全局变量
static struct dentry *pstore_ftrace_dir;	// 定义一个指向文件系统目录项的指针，用于存储 ftrace 的 debugfs 目录

static bool record_ftrace;	// 定义记录 ftrace 的布尔型变量，可以通过模块参数配置
module_param(record_ftrace, bool, 0400);	// 注册模块参数 record_ftrace，类型为布尔型，权限为只读
MODULE_PARM_DESC(record_ftrace,	// 描述模块参数 record_ftrace 的作用
		 "enable ftrace recording immediately (default: off)");	// 模块参数描述：立即启用 ftrace 记录（默认：关闭）

// 注册 pstore 的 ftrace 记录功能
void pstore_register_ftrace(void)
{
	if (!psinfo->write)
		return;	// 如果后端的写函数未定义，则直接返回

	// 在 debugfs 文件系统中创建 pstore 目录
	pstore_ftrace_dir = debugfs_create_dir("pstore", NULL);

	// 根据 record_ftrace 参数值来启用或禁用 ftrace 记录
	pstore_set_ftrace_enabled(record_ftrace);

	// 在 pstore 目录下创建 record_ftrace 文件，权限为 0600
	// 文件操作由 pstore_knob_fops 提供，支持读写操作用于控制 ftrace 记录
	debugfs_create_file("record_ftrace", 0600, pstore_ftrace_dir, NULL,
			    &pstore_knob_fops);
}

// 注销 pstore 的 ftrace 记录功能
void pstore_unregister_ftrace(void)
{
	mutex_lock(&pstore_ftrace_lock);	// 加锁以保护 ftrace 相关操作的线程安全
	if (pstore_ftrace_enabled) {		// 如果 ftrace 记录功能当前已启用
		// 注销 ftrace 函数，停止记录 ftrace 信息
		unregister_ftrace_function(&pstore_ftrace_ops);
		// 设置 ftrace 记录功能为禁用状态
		pstore_ftrace_enabled = false;
	}
	// 解锁
	mutex_unlock(&pstore_ftrace_lock);

	// 递归删除之前创建的 debugfs 目录及其内容
	debugfs_remove_recursive(pstore_ftrace_dir);
}

/*
 * 这段代码用于合并两个 pstore ftrace 日志。它首先计算目标和源日志的有效部分，并为合并结果分配内存。
 * 之后，它按时间戳对记录进行排序并合并。最后，它会释放原目标日志的内存，将目标指针更新为新的合并缓冲区，
 * 并更新大小。这使得函数可以将多个 ftrace 日志合并成一个单一的连续日志，以便于后续处理。
 */
ssize_t pstore_ftrace_combine_log(char **dest_log, size_t *dest_log_size,
				  const char *src_log, size_t src_log_size)
{
	// 初始化变量，用于管理目标和源日志的大小和偏移
	size_t dest_size, src_size, total, dest_off, src_off;
	// 索引用于目标、源和合并后的日志
	size_t dest_idx = 0, src_idx = 0, merged_idx = 0;
	void *merged_buf;  // 合并后的缓冲区
	struct pstore_ftrace_record *drec, *srec, *mrec;  // 记录结构的指针
	size_t record_size = sizeof(struct pstore_ftrace_record);  // 每个记录的大小

	// 计算目标日志的有效大小和偏移
	dest_off = *dest_log_size % record_size;
	dest_size = *dest_log_size - dest_off;

	// 计算源日志的有效大小和偏移
	src_off = src_log_size % record_size;
	src_size = src_log_size - src_off;

	// 计算合并后的总大小
	total = dest_size + src_size;
	// 为合并后的日志分配内存
	merged_buf = kmalloc(total, GFP_KERNEL);
	if (!merged_buf)
		return -ENOMEM;	// 如果内存分配失败，返回错误

	// 初始化指针，指向目标日志、源日志和合并后的日志的开始位置
	drec = (struct pstore_ftrace_record *)(*dest_log + dest_off);
	srec = (struct pstore_ftrace_record *)(src_log + src_off);
	mrec = (struct pstore_ftrace_record *)(merged_buf);

	// 合并两个日志，按时间戳排序
	while (dest_size > 0 && src_size > 0) {
		if (pstore_ftrace_read_timestamp(&drec[dest_idx]) <
		    pstore_ftrace_read_timestamp(&srec[src_idx])) {
			mrec[merged_idx++] = drec[dest_idx++];	// 将较早的记录添加到合并缓冲区
			dest_size -= record_size;	// 减少剩余的目标大小
		} else {
			mrec[merged_idx++] = srec[src_idx++];	// 将较早的记录添加到合并缓冲区
			src_size -= record_size;	// 减少剩余的源大小
		}
	}

	// 如果目标日志还有剩余记录，继续添加
	while (dest_size > 0) {
		mrec[merged_idx++] = drec[dest_idx++];
		dest_size -= record_size;
	}

	// 如果源日志还有剩余记录，继续添加
	while (src_size > 0) {
		mrec[merged_idx++] = srec[src_idx++];
		src_size -= record_size;
	}

	kfree(*dest_log);	// 释放原来的目标日志内存
	// 更新目标日志的指针和大小为合并后的缓冲区和大小
	*dest_log = merged_buf;
	*dest_log_size = total;

	return 0;	// 返回成功
}
EXPORT_SYMBOL_GPL(pstore_ftrace_combine_log);

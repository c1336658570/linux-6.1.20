// SPDX-License-Identifier: GPL-2.0-only
/*
 * Persistent Storage - platform driver interface parts.
 *
 * Copyright (C) 2007-2008 Google, Inc.
 * Copyright (C) 2010 Intel Corporation <tony.luck@intel.com>
 */

// pstore 前后端功能的核心

// 定义日志打印前缀，所有使用pr_系列函数的打印信息前都将加上"pstore: "
#define pr_fmt(fmt) "pstore: " fmt

#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kmsg_dump.h>
#include <linux/console.h>
#include <linux/module.h>
#include <linux/pstore.h>
// 如果启用了LZO压缩，则包含相关头文件
#if IS_ENABLED(CONFIG_PSTORE_LZO_COMPRESS)
#include <linux/lzo.h>
#endif
// 如果启用了LZ4或LZ4HC压缩，则包含相关头文件
#if IS_ENABLED(CONFIG_PSTORE_LZ4_COMPRESS) || IS_ENABLED(CONFIG_PSTORE_LZ4HC_COMPRESS)
#include <linux/lz4.h>
#endif
// 如果启用了ZSTD压缩，则包含相关头文件
#if IS_ENABLED(CONFIG_PSTORE_ZSTD_COMPRESS)
#include <linux/zstd.h>
#endif
#include <linux/crypto.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>

#include "internal.h"

/*
 * We defer making "oops" entries appear in pstore - see
 * whether the system is actually still running well enough
 * to let someone see the entry
 */
/*
 * 我们推迟使“oops”条目在pstore中出现 - 查看系统是否仍然运行得足够好，
 * 允许某人查看该条目
 */
// pstore内容更新前的延迟时间（以毫秒为单位）
static int pstore_update_ms = -1;
// 将update_ms注册为模块参数
module_param_named(update_ms, pstore_update_ms, int, 0600);
// 描述update_ms参数
MODULE_PARM_DESC(update_ms, "milliseconds before pstore updates its content "
		 "(default is -1, which means runtime updates are disabled; "
		 "enabling this option may not be safe; it may lead to further "
		 "corruption on Oopses)");

/* Names should be in the same order as the enum pstore_type_id */
/* 名称应与enum pstore_type_id中的枚举顺序相同 */
static const char * const pstore_type_names[] = {  // pstore记录类型的名称数组
	// 内核日志
	"dmesg",       // 用于内核消息
	// 硬件错误
	"mce",         // 用于机器检查异常
	// 控制台输出
	"console",     // 用于控制台消息
	// 函数调用序列
	"ftrace",      // 用于函数跟踪
	"rtas",        // 用于运行时中断和服务（特定于PowerPC平台）
	"powerpc-ofw", // 用于PowerPC的Open Firmware
	"powerpc-common", // 用于PowerPC的通用记录
	"pmsg",        // 用于持久性消息
	"powerpc-opal" // 用于PowerPC的OPAL固件事件
};

// 定义静态整型变量 pstore_new_entry
static int pstore_new_entry;

// 前置声明一个处理定时器的函数 pstore_timefunc
static void pstore_timefunc(struct timer_list *);
// 定义一个名为 pstore_timer 的定时器，使用 pstore_timefunc 作为处理函数
static DEFINE_TIMER(pstore_timer, pstore_timefunc);

// 前置声明一个处理工作队列项的函数 pstore_dowork
static void pstore_dowork(struct work_struct *);
// 定义一个工作队列项 pstore_work，使用 pstore_dowork 作为处理函数
static DECLARE_WORK(pstore_work, pstore_dowork);

/*
 * psinfo_lock protects "psinfo" during calls to
 * pstore_register(), pstore_unregister(), and
 * the filesystem mount/unmount routines.
 */
/*
 * psinfo_lock 用于在调用 pstore_register(), pstore_unregister(), 
 * 以及文件系统挂载/卸载例程时保护 "psinfo"。
 */
// 定义一个互斥锁 psinfo_lock 用于保护结构体 psinfo
static DEFINE_MUTEX(psinfo_lock);
// 声明指向 pstore_info 结构体的指针 psinfo
struct pstore_info *psinfo;

// 定义指向后端名称的指针变量 backend
static char *backend;
// 将 backend 变量作为模块参数，设置权限为只读
module_param(backend, charp, 0444);
// 对模块参数 backend 进行描述，指明其用途为指定特定的后端
MODULE_PARM_DESC(backend, "specific backend to use");

// 根据是否定义 CONFIG_PSTORE_COMPRESS_DEFAULT，设置压缩方式的默认值
static char *compress =
#ifdef CONFIG_PSTORE_COMPRESS_DEFAULT
		CONFIG_PSTORE_COMPRESS_DEFAULT;
#else
		NULL;
#endif
// 将 compress 变量作为模块参数，设置权限为只读
module_param(compress, charp, 0444);
// 对模块参数 compress 进行描述，指明其用途为指定压缩方式
MODULE_PARM_DESC(compress, "compression to use");

/* Compression parameters */
// 声明一个指向加密压缩结构体的指针 tfm
static struct crypto_comp *tfm;

// 声明一个存储压缩后端信息的结构体 pstore_zbackend
struct pstore_zbackend {
	// 函数指针，用于计算给定大小的缓冲区大小
	int (*zbufsize)(size_t size);
	const char *name;	// 压缩后端的名称
};

// 定义一个指向大型错误缓冲区的字符指针
static char *big_oops_buf;
// 定义大型错误缓冲区的大小
static size_t big_oops_buf_sz;

/* How much of the console log to snapshot */
/* 控制台日志快照的大小 */
// 定义一个记录控制台日志字节数的变量，初始值为 CONFIG_PSTORE_DEFAULT_KMSG_BYTES
unsigned long kmsg_bytes = CONFIG_PSTORE_DEFAULT_KMSG_BYTES;

// 定义一个设置控制台日志字节数的函数
void pstore_set_kmsg_bytes(int bytes)
{
	// 更新控制台日志的字节数
	kmsg_bytes = bytes;
}

/* Tag each group of saved records with a sequence number */
/* 使用序列号标记每组保存的记录 */
static int	oopscount;	// 用于记录崩溃次数的静态变量

/* 根据pstore记录类型返回对应的名称字符串 */
const char *pstore_type_to_name(enum pstore_type_id type)
{
	// 编译时检查类型名称数组的大小是否等于枚举类型的最大值
	BUILD_BUG_ON(ARRAY_SIZE(pstore_type_names) != PSTORE_TYPE_MAX);

	// 如果类型超出有效范围，则输出警告并返回"unknown"
	if (WARN_ON_ONCE(type >= PSTORE_TYPE_MAX))
		return "unknown";

	// 返回对应类型的名称字符串
	return pstore_type_names[type];
}
EXPORT_SYMBOL_GPL(pstore_type_to_name);

/* 根据名称字符串返回对应的pstore记录类型 */
enum pstore_type_id pstore_name_to_type(const char *name)
{
	int i;

	// 遍历所有类型
	for (i = 0; i < PSTORE_TYPE_MAX; i++) {
		// 如果找到匹配的名称
		if (!strcmp(pstore_type_names[i], name))
			return i;	// 返回对应的枚举值
	}

	// 如果未找到匹配的名称，返回枚举的最大值
	return PSTORE_TYPE_MAX;
}
EXPORT_SYMBOL_GPL(pstore_name_to_type);

/* 触发pstore定时器 */
static void pstore_timer_kick(void)
{
	// 如果设定的更新间隔为负值，则不启动定时器
	if (pstore_update_ms < 0)
		return;

	// 重新设置定时器的超时时间
	mod_timer(&pstore_timer, jiffies + msecs_to_jiffies(pstore_update_ms));
}

/* 判断在特定的崩溃原因下pstore是否不应该阻塞 */
static bool pstore_cannot_block_path(enum kmsg_dump_reason reason)
{
	/*
	 * In case of NMI path, pstore shouldn't be blocked
	 * regardless of reason.
	 */
	/*
	 * 在NMI路径中，不论出于何种原因，pstore都不应该被阻塞。
	 */
	if (in_nmi())	// 如果当前处于NMI中，则直接返回true
		return true;

	switch (reason) {
	/* In panic case, other cpus are stopped by smp_send_stop(). */
	/* 在panic情况下，其他CPU会通过smp_send_stop()停止。 */
	case KMSG_DUMP_PANIC:
	/*
	 * Emergency restart shouldn't be blocked by spinning on
	 * pstore_info::buf_lock.
	 */
	/*
	 * 紧急重启不应该因为在pstore_info::buf_lock上自旋而被阻塞。
	 */
	case KMSG_DUMP_EMERG:
		return true;
	default:
		return false;	// 其他情况默认返回false
	}
}

/* 如果启用了DEFLATE压缩，则定义zbufsize_deflate函数 */
#if IS_ENABLED(CONFIG_PSTORE_DEFLATE_COMPRESS)
static int zbufsize_deflate(size_t size)
{
	size_t cmpr;	// 用于计算压缩比的变量

	switch (size) {
	/* buffer range for efivars */
	/* efivars使用的缓冲区范围 */
	case 1000 ... 2000:
		cmpr = 56;	// 在1000到2000字节范围内，设置压缩比为56
		break;
	case 2001 ... 3000:
		cmpr = 54;	// 在2001到3000字节范围内，设置压缩比为54
		break;
	case 3001 ... 3999:
		cmpr = 52;	// 在3001到3999字节范围内，设置压缩比为52
		break;
	/* buffer range for nvram, erst */
	/* nvram和erst使用的缓冲区范围 */
	case 4000 ... 10000:
		cmpr = 45;	// 在4000到10000字节范围内，设置压缩比为45
		break;
	default:
		cmpr = 60;	// 对于其他大小，设置压缩比为60
		break;
	}

	// 根据压缩比计算所需的缓冲区大小
	return (size * 100) / cmpr;
}
#endif


/* 如果启用了LZO压缩，则定义zbufsize_lzo函数 */
#if IS_ENABLED(CONFIG_PSTORE_LZO_COMPRESS)
static int zbufsize_lzo(size_t size)
{
	// 调用LZO库函数计算最坏情况下的压缩大小
	return lzo1x_worst_compress(size);
}
#endif

/* 如果启用了LZ4或LZ4HC压缩，则定义zbufsize_lz4函数 */
#if IS_ENABLED(CONFIG_PSTORE_LZ4_COMPRESS) || IS_ENABLED(CONFIG_PSTORE_LZ4HC_COMPRESS)
static int zbufsize_lz4(size_t size)
{
	// 调用LZ4库函数计算压缩后的最大大小
	return LZ4_compressBound(size);
}
#endif

/* 如果启用了842压缩，则定义zbufsize_842函数 */
#if IS_ENABLED(CONFIG_PSTORE_842_COMPRESS)
static int zbufsize_842(size_t size)
{
	// 842压缩算法不改变数据大小，直接返回输入大小
	return size;
}
#endif

/* 如果启用了ZSTD压缩，定义zbufsize_zstd函数 */
#if IS_ENABLED(CONFIG_PSTORE_ZSTD_COMPRESS)
static int zbufsize_zstd(size_t size)
{
	// 调用ZSTD库函数计算压缩后的最大大小
	return zstd_compress_bound(size);
}
#endif

/* 在初始化后只读的变量，用于指向当前选择的压缩后端 */
static const struct pstore_zbackend *zbackend __ro_after_init;

/* 定义一个数组，包含不同的压缩后端 */
static const struct pstore_zbackend zbackends[] = {
#if IS_ENABLED(CONFIG_PSTORE_DEFLATE_COMPRESS)
	{
		// 指向DEFLATE压缩缓冲区大小计算函数的指针
		.zbufsize	= zbufsize_deflate,
		.name		= "deflate",	// 压缩后端的名称
	},
#endif
#if IS_ENABLED(CONFIG_PSTORE_LZO_COMPRESS)
	{
		// 指向LZO压缩缓冲区大小计算函数的指针
		.zbufsize	= zbufsize_lzo,
		.name		= "lzo",
	},
#endif
#if IS_ENABLED(CONFIG_PSTORE_LZ4_COMPRESS)
	{
		// 指向LZ4压缩缓冲区大小计算函数的指针
		.zbufsize	= zbufsize_lz4,
		.name		= "lz4",
	},
#endif
#if IS_ENABLED(CONFIG_PSTORE_LZ4HC_COMPRESS)
	{
		// 指向LZ4HC压缩缓冲区大小计算函数的指针
		.zbufsize	= zbufsize_lz4,
		.name		= "lz4hc",
	},
#endif
#if IS_ENABLED(CONFIG_PSTORE_842_COMPRESS)
	{
		// 指向842压缩缓冲区大小计算函数的指针
		.zbufsize	= zbufsize_842,
		.name		= "842",
	},
#endif
#if IS_ENABLED(CONFIG_PSTORE_ZSTD_COMPRESS)
	{
		// 指向ZSTD压缩缓冲区大小计算函数的指针
		.zbufsize	= zbufsize_zstd,
		.name		= "zstd",
	},
#endif
	{ }	// 空结构体，表示数组的结束
};

/* 定义一个静态函数，用于压缩数据 */
static int pstore_compress(const void *in, void *out,
			   unsigned int inlen, unsigned int outlen)
{
	int ret;

	/* 如果没有启用压缩功能，返回无效参数错误 */
	if (!IS_ENABLED(CONFIG_PSTORE_COMPRESS))
		return -EINVAL;

	/* 调用压缩函数进行压缩，输入数据为in，输入长度为inlen，输出缓冲区为out，输出长度为outlen */
	ret = crypto_comp_compress(tfm, in, inlen, out, &outlen);
	if (ret) {	// 如果压缩过程中有错误发生
		// 打印错误日志
		pr_err("crypto_comp_compress failed, ret = %d!\n", ret);
		return ret;
	}

	return outlen;	// 如果压缩成功，返回压缩后的数据长度
}

/* 分配压缩用缓冲区的函数 */
static void allocate_buf_for_compression(void)
{
	struct crypto_comp *ctx;	// 压缩上下文
	int size;	// 缓冲区大小
	char *buf;	// 指向缓冲区的指针

	/* Skip if not built-in or compression backend not selected yet. */
	/* 如果压缩功能未启用或未选择压缩后端，则跳过 */
	if (!IS_ENABLED(CONFIG_PSTORE_COMPRESS) || !zbackend)
		return;

	/* Skip if no pstore backend yet or compression init already done. */
	/* 如果没有pstore后端或已经初始化压缩，则跳过 */
	if (!psinfo || tfm)
		return;

	/* 检查是否支持指定的压缩算法，如果不支持，打印错误信息并返回 */
	if (!crypto_has_comp(zbackend->name, 0, 0)) {
		pr_err("Unknown compression: %s\n", zbackend->name);
		return;
	}

	/* 调用压缩后端的函数计算所需的缓冲区大小 */
	size = zbackend->zbufsize(psinfo->bufsize);
	if (size <= 0) {
		pr_err("Invalid compression size for %s: %d\n",
		       zbackend->name, size);
		return;
	}

	/* 为压缩分配内存 */
	buf = kmalloc(size, GFP_KERNEL);
	if (!buf) {
		pr_err("Failed %d byte compression buffer allocation for: %s\n",
		       size, zbackend->name);
		return;
	}

	/* 分配压缩上下文 */
	ctx = crypto_alloc_comp(zbackend->name, 0, 0);
	if (IS_ERR_OR_NULL(ctx)) {
		kfree(buf);	// 如果分配失败，释放之前分配的缓冲区
		pr_err("crypto_alloc_comp('%s') failed: %ld\n", zbackend->name,
		       PTR_ERR(ctx));
		return;
	}

	/* A non-NULL big_oops_buf indicates compression is available. */
	/* 设置全局变量，表示压缩上下文和缓冲区已准备好 */
	tfm = ctx;
	big_oops_buf_sz = size;
	big_oops_buf = buf;

	/* 打印使用的压缩算法 */
	pr_info("Using crash dump compression: %s\n", zbackend->name);
}

/* 释放压缩用的缓冲区 */
static void free_buf_for_compression(void)
{
	if (IS_ENABLED(CONFIG_PSTORE_COMPRESS) && tfm) {  // 如果启用了压缩并且有压缩上下文存在
		crypto_free_comp(tfm);  // 释放压缩上下文
		tfm = NULL;  // 将压缩上下文指针设置为NULL
	}
	kfree(big_oops_buf);  // 释放用于存储压缩数据的缓冲区
	big_oops_buf = NULL;  // 将缓冲区指针设置为NULL
	big_oops_buf_sz = 0;  // 将缓冲区大小设置为0
}

/*
 * Called when compression fails, since the printk buffer
 * would be fetched for compression calling it again when
 * compression fails would have moved the iterator of
 * printk buffer which results in fetching old contents.
 * Copy the recent messages from big_oops_buf to psinfo->buf
 */
/*
 * 当压缩失败时调用，因为printk缓冲区在调用压缩时被提取，
 * 如果压缩失败再次调用会导致printk缓冲区的迭代器移动，
 * 从而导致获取到的是旧内容。
 * 将big_oops_buf中的最新消息复制到psinfo->buf中
 */
// 用于在压缩失败时恢复原始的内核消息
static size_t copy_kmsg_to_buffer(int hsize, size_t len)
{
	size_t total_len;	// 总长度
	size_t diff;			// 差值

	total_len = hsize + len;	// 计算总长度

	// 如果总长度超过psinfo的缓冲区大小
	if (total_len > psinfo->bufsize) {
		// 计算差值
		diff = total_len - psinfo->bufsize + hsize;
		// 先复制头部数据
		memcpy(psinfo->buf, big_oops_buf, hsize);
		// 再复制主体数据，确保不超出缓冲区
		memcpy(psinfo->buf + hsize, big_oops_buf + diff,
					psinfo->bufsize - hsize);
		// 设置总长度为psinfo缓冲区的大小
		total_len = psinfo->bufsize;
	} else
		// 如果不超过，直接复制全部数据
		memcpy(psinfo->buf, big_oops_buf, total_len);

	return total_len;	// 返回复制的数据长度
}

/* 初始化pstore记录 */
void pstore_record_init(struct pstore_record *record,
			struct pstore_info *psinfo)
{
	// 清零pstore记录结构
	memset(record, 0, sizeof(*record));

	// 设置pstore后端信息
	record->psi = psinfo;

	/* Report zeroed timestamp if called before timekeeping has resumed. */
	/* 如果在时间记录恢复前调用，报告时间戳为零。 */
	// 获取并设置当前时间
	record->time = ns_to_timespec64(ktime_get_real_fast_ns());
}

/*
 * callback from kmsg_dump. Save as much as we can (up to kmsg_bytes) from the
 * end of the buffer.
 */
/*
 * 从kmsg_dump调用的回调函数。尽可能多地保存来自缓冲区末尾的数据（直至kmsg_bytes的限制）。
 */
// 它是一个回调函数，用于从内核消息转储（kmsg dump）中保存尽可能多的信息（直到 
// kmsg_bytes 定义的限制）。这是在系统发生崩溃或其他严重错误时调用的。
static void pstore_dump(struct kmsg_dumper *dumper,
			enum kmsg_dump_reason reason)
{
	struct kmsg_dump_iter iter;	// 用于迭代kmsg_dump的结构体
	unsigned long	total = 0;		// 已保存的总字节数
	const char	*why;						// 原因描述字符串
	unsigned int	part = 1;			// 分段数
	unsigned long	flags = 0;		// 用于保存中断状态
	int		ret;									// 函数调用的返回值

	// 获取原因的字符串表示
	why = kmsg_dump_reason_str(reason);

	// 如果处于不能阻塞的路径
	if (pstore_cannot_block_path(reason)) {
		// 尝试获取锁，保存中断状态
		if (!spin_trylock_irqsave(&psinfo->buf_lock, flags)) {
			pr_err("dump skipped in %s path because of concurrent dump\n",
					in_nmi() ? "NMI" : why);
			return;
		}
	} else {
		// 获取锁，保存中断状态
		spin_lock_irqsave(&psinfo->buf_lock, flags);
	}

	// 重置kmsg_dump的迭代器
	kmsg_dump_rewind(&iter);

	oopscount++;	// 增加崩溃计数
	while (total < kmsg_bytes) {	// 在未达到限制的情况下继续保存数据
		char *dst;  // 目的缓冲区指针
		size_t dst_size;  // 目的缓冲区大小
		int header_size;  // 头部信息大小
		int zipped_len = -1;  // 压缩后长度
		size_t dump_size;  // 转储大小
		struct pstore_record record;  // pstore记录结构

		pstore_record_init(&record, psinfo);  // 初始化记录
		record.type = PSTORE_TYPE_DMESG;  // 设置记录类型为内核消息
		record.count = oopscount;  // 设置崩溃计数
		record.reason = reason;  // 设置原因
		record.part = part;  // 设置部分
		record.buf = psinfo->buf;  // 设置缓冲区

		if (big_oops_buf) {
			dst = big_oops_buf;	// 设置目的地为大的Oops缓冲区
			dst_size = big_oops_buf_sz;	// 设置大小为大的Oops缓冲区大小
		} else {
			dst = psinfo->buf;	// 使用默认缓冲区
			dst_size = psinfo->bufsize;	// 使用默认缓冲区大小
		}

		/* Write dump header. */
		/* 写入转储头部。 */
		header_size = snprintf(dst, dst_size, "%s#%d Part%u\n", why,
				 oopscount, part);
		dst_size -= header_size;	// 调整剩余空间大小

		/* Write dump contents. */
		/* 写入转储内容。 */
		if (!kmsg_dump_get_buffer(&iter, true, dst + header_size,
					  dst_size, &dump_size))
			break;	// 如果无法获取更多内容，则停止

		if (big_oops_buf) {
			// 如果使用大的Oops缓冲区，尝试进行压缩
			zipped_len = pstore_compress(dst, psinfo->buf,
						header_size + dump_size,
						psinfo->bufsize);

			if (zipped_len > 0) {
				// 标记为已压缩
				record.compressed = true;
				record.size = zipped_len;
			} else {
				// 如果压缩失败，则直接使用原始数据
				record.size = copy_kmsg_to_buffer(header_size,
								  dump_size);
			}
		} else {
			// 如果不使用大的Oops缓冲区，则直接设置记录大小
			record.size = header_size + dump_size;
		}

		// 写入记录
		ret = psinfo->write(&record);
		if (ret == 0 && reason == KMSG_DUMP_OOPS) {
			pstore_new_entry = 1;	// 标记新条目
			pstore_timer_kick();	// 触发定时器
		}

		total += record.size;		// 更新已保存的总字节
		part++;		// 更新分段计数
	}
	spin_unlock_irqrestore(&psinfo->buf_lock, flags);	// 释放锁，并恢复之前的中断状态
}

/* 定义一个kmsg_dumper结构体，用于处理内核消息转储 */
static struct kmsg_dumper pstore_dumper = {
	// 指定转储函数为pstore_dump
	.dump = pstore_dump,
};

/*
 * Register with kmsg_dump to save last part of console log on panic.
 */
/*
 * 注册kmsg_dumper以在系统panic时保存控制台日志的最后部分。
 */
static void pstore_register_kmsg(void)
{
	// 调用kmsg_dump_register函数注册pstore_dumper
	kmsg_dump_register(&pstore_dumper);
}

/* 注销kmsg_dumper */
static void pstore_unregister_kmsg(void)
{
	// 调用kmsg_dump_unregister函数注销pstore_dumper
	kmsg_dump_unregister(&pstore_dumper);
}

#ifdef CONFIG_PSTORE_CONSOLE
/* 定义一个函数，用于将控制台输出写入pstore */
static void pstore_console_write(struct console *con, const char *s, unsigned c)
{
	struct pstore_record record;	// 定义一个pstore记录

	if (!c)
		return;

	pstore_record_init(&record, psinfo);	// 初始化pstore记录
	record.type = PSTORE_TYPE_CONSOLE;  // 设置记录类型为控制台输出

	record.buf = (char *)s;  // 设置记录的缓冲区为输入字符串
	record.size = c;  // 设置记录的大小为输入字符串的长度
	psinfo->write(&record);  // 调用psinfo的写函数将记录写入pstore
}

/* 定义一个控制台结构体，指定写入函数 */
static struct console pstore_console = {
	.write	= pstore_console_write,	// 设置写入函数为pstore_console_write
	.index	= -1,										// 控制台索引设置为-1
};

/* 注册pstore控制台 */
static void pstore_register_console(void)
{
	/* Show which backend is going to get console writes. */
	/* 显示哪个后端将接收控制台写入 */
	strscpy(pstore_console.name, psinfo->name,
		sizeof(pstore_console.name));	// 将psinfo的名称复制到控制台的名称中
	/*
	 * Always initialize flags here since prior unregister_console()
	 * calls may have changed settings (specifically CON_ENABLED).
	 */
	/*
   * 总是在这里初始化标志，因为之前的unregister_console()调用可能改变了设置
   * （特别是CON_ENABLED）。
   */
	// 设置控制台标志
	pstore_console.flags = CON_PRINTBUFFER | CON_ENABLED | CON_ANYTIME;
	register_console(&pstore_console);	// 注册控制台
}

/* 注销pstore控制台 */
static void pstore_unregister_console(void)
{
	unregister_console(&pstore_console);	// 注销控制台
}
#else
/* 如果CONFIG_PSTORE_CONSOLE未定义，定义空的注册和注销函数 */
static void pstore_register_console(void) {}
static void pstore_unregister_console(void) {}
#endif

/*
 * 这个函数是兼容旧版的写入函数，它从用户空间获取数据并写入pstore。
 * 它首先检查传入的pstore记录的缓冲区是否为空，如果不为空则返回错误。
 * 如果为空，则从用户空间复制数据到新分配的内核空间缓冲区。
 * 在成功复制数据后，调用pstore的写函数将数据写入存储。
 * 写入完成后释放分配的缓冲区，并根据操作结果返回相应的状态。
 */
static int pstore_write_user_compat(struct pstore_record *record,
				    const char __user *buf)
{
	int ret = 0;	// 函数返回值初始化为0

	if (record->buf)	// 如果记录的缓冲区已经被分配
		return -EINVAL;	// 返回无效参数错误

	// 从用户空间复制数据到新分配的内核空间缓冲区
	record->buf = memdup_user(buf, record->size);
	if (IS_ERR(record->buf)) {	// 如果复制过程出错
		ret = PTR_ERR(record->buf);	// 获取错误码
		goto out;	// 跳转到清理代码
	}

	// 调用pstore后端的写函数将数据写入存储
	ret = record->psi->write(record);

	kfree(record->buf);	// 释放之前分配的缓冲区
out:
	record->buf = NULL;	// 将记录的缓冲区指针置为空

	// 如果函数执行出错，返回错误码；否则返回写入的字节数
	return unlikely(ret < 0) ? ret : record->size;
}

/*
 * platform specific persistent storage driver registers with
 * us here. If pstore is already mounted, call the platform
 * read function right away to populate the file system. If not
 * then the pstore mount code will call us later to fill out
 * the file system.
 */
/*
 * 平台特定的持久存储驱动在这里注册。
 * 如果pstore已经挂载，立即调用平台的读取函数以填充文件系统。
 * 如果没有挂载，则pstore挂载代码稍后会调用此函数来填充文件系统。
 */
int pstore_register(struct pstore_info *psi)
{
	// 如果已有其他后端注册并且名称不匹配
	if (backend && strcmp(backend, psi->name)) {
		// 打印警告信息
		pr_warn("ignoring unexpected backend '%s'\n", psi->name);
		return -EPERM;	// 返回错误，不允许执行
	}

	/* Sanity check flags. */
	/* 校验标志位 */
	if (!psi->flags) {	// 如果没有支持任何前端
		pr_warn("backend '%s' must support at least one frontend\n",
			psi->name);
		return -EINVAL;	// 返回无效参数错误
	}

	/* Check for required functions. */
	/* 检查必须实现的函数 */
	if (!psi->read || !psi->write) {	// 如果没有实现read()或write()函数
		pr_warn("backend '%s' must implement read() and write()\n",
			psi->name);
		return -EINVAL;		// 返回无效参数错误
	}

	// 锁定互斥锁以保护全局变量psinfo
	mutex_lock(&psinfo_lock);
	if (psinfo) {	// 如果已有后端注册
		pr_warn("backend '%s' already loaded: ignoring '%s'\n",
			psinfo->name, psi->name);
		mutex_unlock(&psinfo_lock);	// 解锁互斥锁
		return -EBUSY;	// 返回设备忙错误
	}

	// 如果没有实现write_user函数
	if (!psi->write_user)
		// 使用兼容函数
		psi->write_user = pstore_write_user_compat;
	psinfo = psi;	// 设置全局后端信息
	// 初始化读取互斥锁
	mutex_init(&psinfo->read_mutex);
	// 初始化缓冲区自旋锁
	spin_lock_init(&psinfo->buf_lock);

	// 如果支持内核消息记录
	if (psi->flags & PSTORE_FLAGS_DMESG)
		// 分配用于压缩的缓冲区
		allocate_buf_for_compression();

	pstore_get_records(0);	// 尝试获取现有记录

	if (psi->flags & PSTORE_FLAGS_DMESG) {	// 如果支持内核消息记录
		// 设置转储器的最大原因
		pstore_dumper.max_reason = psinfo->max_reason;
		// 注册内核消息转储
		pstore_register_kmsg();
	}
	// 如果支持控制台记录
	if (psi->flags & PSTORE_FLAGS_CONSOLE)
		pstore_register_console();
	// 如果支持函数跟踪记录
	if (psi->flags & PSTORE_FLAGS_FTRACE)
		pstore_register_ftrace();
	// 如果支持持久消息记录
	if (psi->flags & PSTORE_FLAGS_PMSG)
		pstore_register_pmsg();

	/* Start watching for new records, if desired. */
	/* 如果需要，开始监视新记录 */
	pstore_timer_kick();

	/*
	 * Update the module parameter backend, so it is visible
	 * through /sys/module/pstore/parameters/backend
	 */
	/*
	 * 更新模块参数backend，使其通过/sys/module/pstore/parameters/backend可见
	 */
	// 复制后端名称到全局变量
	backend = kstrdup(psi->name, GFP_KERNEL);

	// 打印注册成功信息
	pr_info("Registered %s as persistent store backend\n", psi->name);

	mutex_unlock(&psinfo_lock);	// 解锁互斥锁
	return 0;	// 返回成功
}
EXPORT_SYMBOL_GPL(pstore_register);

/* 注销 pstore 后端的函数 */
void pstore_unregister(struct pstore_info *psi)
{
	/* It's okay to unregister nothing. */
	/* 如果尝试注销一个空指针，直接返回。 */
	if (!psi)
		return;

	// 获取互斥锁以保护全局变量 psinfo
	mutex_lock(&psinfo_lock);

	/* Only one backend can be registered at a time. */
	/* 如果尝试注销的后端不是当前注册的后端，打印警告信息并返回 */
	if (WARN_ON(psi != psinfo)) {
		mutex_unlock(&psinfo_lock);	// 释放互斥锁
		return;
	}

	/* Unregister all callbacks. */
	/* 注销所有回调函数。 */
	if (psi->flags & PSTORE_FLAGS_PMSG)
		pstore_unregister_pmsg();  // 注销持久消息记录回调
	if (psi->flags & PSTORE_FLAGS_FTRACE)
		pstore_unregister_ftrace();  // 注销函数跟踪记录回调
	if (psi->flags & PSTORE_FLAGS_CONSOLE)
		pstore_unregister_console();  // 注销控制台记录回调
	if (psi->flags & PSTORE_FLAGS_DMESG)
		pstore_unregister_kmsg();  // 注销内核消息记录回调

	/* Stop timer and make sure all work has finished. */
	/* 停止定时器并确保所有相关工作已完成。 */
	del_timer_sync(&pstore_timer);	// 同步删除定时器
	flush_work(&pstore_work);				// 清理所有未完成的工作

	/* Remove all backend records from filesystem tree. */
	/* 从文件系统树中移除所有后端记录。 */
	pstore_put_backend_records(psi);	// 清理后端记录

	free_buf_for_compression();	// 释放压缩用的缓冲区

	psinfo = NULL;  // 清空全局变量 psinfo
	kfree(backend);  // 释放后端名称字符串
	backend = NULL;  // 将后端名称指针置为空
	mutex_unlock(&psinfo_lock);  // 释放互斥锁
}
EXPORT_SYMBOL_GPL(pstore_unregister);

/* 解压 pstore 记录的函数 */
static void decompress_record(struct pstore_record *record)
{
	int ret;  // 用于保存函数调用结果
	int unzipped_len;  // 解压后的长度
	char *unzipped, *workspace;  // 解压缓冲区和工作空间指针

	/* 如果没有启用压缩功能或记录未压缩，则直接返回 */
	if (!IS_ENABLED(CONFIG_PSTORE_COMPRESS) || !record->compressed)
		return;

	/* Only PSTORE_TYPE_DMESG support compression. */
	/* 只有 PSTORE_TYPE_DMESG 类型支持压缩 */
	if (record->type != PSTORE_TYPE_DMESG) {
		pr_warn("ignored compressed record type %d\n", record->type);
		return;
	}

	/* Missing compression buffer means compression was not initialized. */
	/* 如果缺少压缩缓冲区，则表明压缩未初始化 */
	if (!big_oops_buf) {
		pr_warn("no decompression method initialized!\n");
		return;
	}

	/* Allocate enough space to hold max decompression and ECC. */
	/* 分配足够的空间以存储最大解压长度和 ECC 通知 */
	unzipped_len = big_oops_buf_sz;
	workspace = kmalloc(unzipped_len + record->ecc_notice_size,
			    GFP_KERNEL);
	if (!workspace)
		return;

	/* After decompression "unzipped_len" is almost certainly smaller. */
	/* 解压后的长度 "unzipped_len" 几乎肯定会更小 */
	ret = crypto_comp_decompress(tfm, record->buf, record->size,
					  workspace, &unzipped_len);
	if (ret) {
		pr_err("crypto_comp_decompress failed, ret = %d!\n", ret);
		kfree(workspace);	// 如果解压失败，释放工作空间
		return;
	}

	/* Append ECC notice to decompressed buffer. */
	/* 在解压缓冲区后附加 ECC 通知 */
	memcpy(workspace + unzipped_len, record->buf + record->size,
	       record->ecc_notice_size);

	/* Copy decompressed contents into an minimum-sized allocation. */
	/* 将解压内容复制到最小大小的分配中 */
	unzipped = kmemdup(workspace, unzipped_len + record->ecc_notice_size,
			   GFP_KERNEL);
	kfree(workspace);	// 释放工作空间
	if (!unzipped)
		return;

	/* Swap out compressed contents with decompressed contents. */
	/* 用解压内容替换压缩内容 */
	kfree(record->buf);  // 释放原压缩内容
	record->buf = unzipped;  // 更新记录的缓冲区指针为解压后的缓冲区
	record->size = unzipped_len;  // 更新记录大小为解压后的大小
	record->compressed = false;  // 设置记录为未压缩状态
}

/*
 * Read all the records from one persistent store backend. Create
 * files in our filesystem.  Don't warn about -EEXIST errors
 * when we are re-scanning the backing store looking to add new
 * error records.
 */
/*
 * 从一个持久存储后端读取所有记录。在我们的文件系统中创建文件。
 * 当我们重新扫描后端存储以寻找新增的错误记录时，不要对 -EEXIST 错误发出警告。
 */
void pstore_get_backend_records(struct pstore_info *psi,
				struct dentry *root, int quiet)
{
	int failed = 0;	// 失败计数
	// 设置循环停止阈值以防止无限循环
	unsigned int stop_loop = 65536;

	// 如果传入的后端信息或根目录为空，直接返回
	if (!psi || !root)
		return;

	// 锁定后端的读取互斥锁
	mutex_lock(&psi->read_mutex);
	// 如果存在打开函数并且打开失败
	if (psi->open && psi->open(psi))
		goto out;

	/*
	 * Backend callback read() allocates record.buf. decompress_record()
	 * may reallocate record.buf. On success, pstore_mkfile() will keep
	 * the record.buf, so free it only on failure.
	 */
	/*
	 * 后端回调 read() 分配 record.buf。decompress_record()
	 * 可能会重新分配 record.buf。如果成功，pstore_mkfile() 将保留
	 * record.buf，因此仅在失败时释放它。
	 */
	// 使用计数器防止潜在的无限循环
	for (; stop_loop; stop_loop--) {
		struct pstore_record *record;
		int rc;

		// 分配并初始化记录
		record = kzalloc(sizeof(*record), GFP_KERNEL);
		if (!record) {
			// 内存分配失败时打印错误
			pr_err("out of memory creating record\n");
			break;
		}
		// 初始化记录
		pstore_record_init(record, psi);

		// 从后端读取记录
		record->size = psi->read(record);

		/* No more records left in backend? */
		/* 后端没有更多记录了吗？ */
		if (record->size <= 0) {
			kfree(record);	// 释放记录内存
			break;
		}

		decompress_record(record);	// 解压记录
		// 在文件系统中创建文件
		rc = pstore_mkfile(root, record);
		if (rc) {
			/* pstore_mkfile() did not take record, so free it. */
			/* pstore_mkfile() 没有接受记录，因此释放它。 */
			kfree(record->buf);
			kfree(record->priv);
			kfree(record);
			// 如果失败不是因为文件已存在，或不在安静模式下
			if (rc != -EEXIST || !quiet)
				failed++;
		}
	}
	// 如果存在关闭函数，则调用关闭
	if (psi->close)
		psi->close(psi);
out:
	// 解锁读取互斥锁
	mutex_unlock(&psi->read_mutex);

	if (failed)
		// 如果有失败的操作
		pr_warn("failed to create %d record(s) from '%s'\n",
			failed, psi->name);
	if (!stop_loop)
		// 如果循环计数器耗尽
		pr_err("looping? Too many records seen from '%s'\n",
			psi->name);
}

/* 执行 pstore 模块的工作队列项 */
static void pstore_dowork(struct work_struct *work)
{
	// 调用 pstore_get_records 函数处理记录，参数 1 表示操作模式（可能表示处理所有记录）
	pstore_get_records(1);
}

/* pstore 定时器函数 */
static void pstore_timefunc(struct timer_list *unused)
{
	if (pstore_new_entry) {  // 如果有新的记录需要处理
		pstore_new_entry = 0;  // 重置新记录标志
		schedule_work(&pstore_work);  // 调度工作队列项，即调用 pstore_dowork 函数
	}

	pstore_timer_kick();  // 重新激活定时器，确保持续监控
}

/* 选择压缩算法的初始化函数 */
static void __init pstore_choose_compression(void)
{
	// 用于遍历支持的压缩后端
	const struct pstore_zbackend *step;

	if (!compress)	// 如果没有指定压缩算法
		return;

	// 遍历所有已注册的压缩后端
	for (step = zbackends; step->name; step++) {
		// 如果找到匹配的压缩后端
		if (!strcmp(compress, step->name)) {
			zbackend = step;	// 设置当前使用的压缩后端
			return;
		}
	}
}

static int __init pstore_init(void)
{
	int ret;

	// 选择合适的压缩算法
	pstore_choose_compression();

	/*
	 * Check if any pstore backends registered earlier but did not
	 * initialize compression because crypto was not ready. If so,
	 * initialize compression now.
	 */

	/*
	 * 检查是否有任何pstore后端之前注册但由于加密功能未就绪而未初始化压缩。
	 * 如果是这种情况，现在初始化压缩。
	 */
	allocate_buf_for_compression();	// 为压缩分配缓冲区

	ret = pstore_init_fs();	// 初始化pstore文件系统
	if (ret)	// 如果初始化失败
		// 释放为压缩分配的缓冲区
		free_buf_for_compression();

	return ret;	// 返回初始化结果
}
late_initcall(pstore_init);

static void __exit pstore_exit(void)
{
	pstore_exit_fs();	// 退出pstore文件系统
}
module_exit(pstore_exit)

MODULE_AUTHOR("Tony Luck <tony.luck@intel.com>");
MODULE_LICENSE("GPL");

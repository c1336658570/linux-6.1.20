// SPDX-License-Identifier: GPL-2.0-only
/*
 * RAM Oops/Panic logger
 *
 * Copyright (C) 2010 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright (C) 2011 Kees Cook <keescook@chromium.org>
 */

// pstore/ram 后端的实现,dram空间分配与管理

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/pstore.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/pstore_ram.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include "internal.h"

#define RAMOOPS_KERNMSG_HDR "===="  // 定义内核消息头部的分隔符
#define MIN_MEM_SIZE 4096UL  // 定义最小内存大小常量

static ulong record_size = MIN_MEM_SIZE;  // 定义用于记录大小的变量，默认为最小内存大小
module_param(record_size, ulong, 0400);  // 注册内核模块参数，允许在加载模块时设置`record_size`
MODULE_PARM_DESC(record_size,
		"size of each dump done on oops/panic");  // 添加对模块参数的描述：每次崩溃或错误转储的大小

static ulong ramoops_console_size = MIN_MEM_SIZE;  // 定义内核控制台日志的大小，默认为最小内存大小
module_param_named(console_size, ramoops_console_size, ulong, 0400);  // 以具名方式注册内核模块参数
MODULE_PARM_DESC(console_size, "size of kernel console log");  // 添加对模块参数的描述：内核控制台日志的大小

static ulong ramoops_ftrace_size = MIN_MEM_SIZE;  // 定义ftrace日志的大小，默认为最小内存大小
module_param_named(ftrace_size, ramoops_ftrace_size, ulong, 0400);  // 以具名方式注册内核模块参数
MODULE_PARM_DESC(ftrace_size, "size of ftrace log");  // 添加对模块参数的描述：ftrace日志的大小

static ulong ramoops_pmsg_size = MIN_MEM_SIZE;  // 定义用户空间消息日志的大小，默认为最小内存大小
module_param_named(pmsg_size, ramoops_pmsg_size, ulong, 0400);  // 以具名方式注册内核模块参数
MODULE_PARM_DESC(pmsg_size, "size of user space message log");  // 添加对模块参数的描述：用户空间消息日志的大小

static unsigned long long mem_address;  // 定义用于存储oops/panic日志的保留RAM的起始地址
module_param_hw(mem_address, ullong, other, 0400);  // 注册硬件相关的内核模块参数
MODULE_PARM_DESC(mem_address,
		"start of reserved RAM used to store oops/panic logs");  // 添加对模块参数的描述：用于存储崩溃日志的保留RAM的起始地址

static ulong mem_size;	// 定义一个变量mem_size用于存储为oops/panic日志预留的RAM大小。
module_param(mem_size, ulong, 0400);	// 通过module_param注册mem_size为模块参数，设置其权限为只读（0400）。
// 使用MODULE_PARM_DESC为mem_size添加描述："用于存储崩溃/恐慌日志的保留RAM大小"。
MODULE_PARM_DESC(mem_size,
		"size of reserved RAM used to store oops/panic logs");

static unsigned int mem_type;	// 定义一个变量mem_type用于指定内存的类型。
module_param(mem_type, uint, 0400);	// 注册mem_type为模块参数，设置权限为只读。
// 添加描述："内存类型：0=写合并（默认），1=未缓冲，2=缓存"。
MODULE_PARM_DESC(mem_type,
		"memory type: 0=write-combined (default), 1=unbuffered, 2=cached");

static int ramoops_max_reason = -1;	// 定义一个变量ramoops_max_reason用于指定内核消息转储的最大原因。
// 使用module_param_named注册此参数，允许通过max_reason设置此变量。
module_param_named(max_reason, ramoops_max_reason, int, 0400);
// 添加描述："内核消息转储的最大原因（默认2：Oops和Panic）"。
MODULE_PARM_DESC(max_reason,
		 "maximum reason for kmsg dump (default 2: Oops and Panic) ");

static int ramoops_ecc;	// 定义一个变量ramoops_ecc用于配置ECC支持。
// 注册ecc参数，设置为只读，并通过描述说明："如果非零，此选项启用ECC支持并指定"
module_param_named(ecc, ramoops_ecc, int, 0400);
MODULE_PARM_DESC(ramoops_ecc,	// "ECC缓冲区大小（以字节为单位，1是特殊值，意味着16字节ECC）"。
		"if non-zero, the option enables ECC support and specifies "
		"ECC buffer size in bytes (1 is a special value, means 16 "
		"bytes ECC)");

static int ramoops_dump_oops = -1;	// 定义一个变量ramoops_dump_oops用于控制是否转储oops和panic。
// 注册dump_oops为模块参数，并标记为已弃用，建议使用max_reason参数。
module_param_named(dump_oops, ramoops_dump_oops, int, 0400);
// 添加描述："（已弃用：改用max_reason）设置为1以转储oops和panic，设置为0仅转储panic"。
MODULE_PARM_DESC(dump_oops,
		 "(deprecated: use max_reason instead) set to 1 to dump oopses & panics, 0 to only dump panics");

struct ramoops_context {
	// 指向Oops转储区域数组的指针，每个元素都是一个指向persistent_ram_zone的指针
	struct persistent_ram_zone **dprzs;	/* Oops dump zones */
	// 指向控制台区域的指针，用于记录内核控制台输出
	struct persistent_ram_zone *cprz;	/* Console zone */
	// 指向Ftrace转储区域数组的指针，每个元素都是一个指向persistent_ram_zone的指针
	struct persistent_ram_zone **fprzs;	/* Ftrace zones */
	// 指向PMSG区域的指针，用于存储来自用户空间的消息
	struct persistent_ram_zone *mprz;	/* PMSG zone */
	// 物理地址，表示ramoops使用的内存区域的起始物理地址
	phys_addr_t phys_addr;
	// 总大小，表示ramoops使用的内存区域的总大小
	unsigned long size;
	// 内存类型，如写组合、非缓存等，影响内存映射的行为
	unsigned int memtype;
	// Oops记录的大小，每个Oops记录的内存大小
	size_t record_size;
	// 控制台记录的大小，控制台日志记录的内存大小
	size_t console_size;
	// Ftrace记录的大小，Ftrace日志记录的内存大小
	size_t ftrace_size;
	// PMSG记录的大小，用户空间消息记录的内存大小
	size_t pmsg_size;
	// 标志位，用于控制ramoops的行为，如自动清除旧数据等
	u32 flags;
	// ECC配置信息，包括ECC大小、块大小等，用于纠错编码
	struct persistent_ram_ecc_info ecc_info;
	// 最大转储计数，表示Oops区域的最大数量
	unsigned int max_dump_cnt;
	// 转储写入计数，记录已经写入的Oops转储的数量
	unsigned int dump_write_cnt;
	/* _read_cnt need clear on ramoops_pstore_open */
	// 转储读取计数，记录已经读取的Oops转储的数量
	unsigned int dump_read_cnt;
	// 控制台读取计数，记录已经读取的控制台日志的数量
	unsigned int console_read_cnt;
	// 最大Ftrace计数，表示Ftrace区域的最大数量
	unsigned int max_ftrace_cnt;
	// Ftrace读取计数，记录已经读取的Ftrace日志的数量
	unsigned int ftrace_read_cnt;
	// PMSG读取计数，记录已经读取的PMSG日志的数量
	unsigned int pmsg_read_cnt;
	// pstore信息结构体，提供接口给pstore注册和注销操作等
	struct pstore_info pstore;
};

// 定义一个静态的平台设备指针，名为dummy，可能用于保留或未特别指定的平台设备引用。
static struct platform_device *dummy;

// 定义了一个函数，该函数用于初始化ramoops模块在打开存储接口时的一些状态，特别是读取计数器的重置。
static int ramoops_pstore_open(struct pstore_info *psi)
{
	// 从pstore信息结构中获取ramoops上下文，该结构体包含所有相关的状态和配置
	struct ramoops_context *cxt = psi->data;

	cxt->dump_read_cnt = 0;	// 将Oops转储的读取计数重置为0，意味着所有的读取状态被清空
	cxt->console_read_cnt = 0;	// 将控制台日志的读取计数重置为0
	cxt->ftrace_read_cnt = 0;	// 将ftrace日志的读取计数重置为0
	cxt->pmsg_read_cnt = 0;		// 将用户空间消息（pmsg）的读取计数重置为0
	return 0;			// 返回0表示成功执行了打开操作并初始化了读取计数器
}

// 定义了一个函数，用于获取指定索引处的persistent_ram_zone结构体实例。它主要用在处理内核存储日志记录时，来检索和更新特定的存储区域。
// 定义一个函数，用于获取数组中指定索引的持久性RAM区域
/*
 * 此函数用于pstore日志系统中，便于遍历和管理各种类型的日志记录区域。
 * 通过传递索引和记录数组，函数可以检索相应的日志区域，更新旧日志，并准备相应的记录信息以供进一步处理。
 */
static struct persistent_ram_zone *
ramoops_get_next_prz(struct persistent_ram_zone *przs[], int id,
		     struct pstore_record *record)
{
	struct persistent_ram_zone *prz;	// 声明一个指向persistent_ram_zone的指针

	/* Give up if we never existed or have hit the end. */
	// 如果传入的数组为空或者已经到达数组末尾，直接返回NULL
	if (!przs)
		return NULL;

	prz = przs[id];	// 获取数组中指定索引的持久性RAM区域
	if (!prz)
		return NULL;	// 如果指定索引处的区域为空，返回NULL

	/* Update old/shadowed buffer. */
	// 更新旧的或被遮蔽的缓冲区
	if (prz->type == PSTORE_TYPE_DMESG)
		persistent_ram_save_old(prz);	// 如果区域类型为DMESG（即内核消息），则保存旧的日志信息

	if (!persistent_ram_old_size(prz))
		return NULL;	// 如果没有旧的日志大小（即旧日志为空），返回NULL

	record->type = prz->type;	// 设置pstore记录的类型为当前区域的类型
	record->id = id;	// 设置pstore记录的ID为当前索引

	return prz;	// 返回找到的持久性RAM区域
}

// 义了一个函数，用于从提供的缓冲区中解析内核消息（kmsg）的头部信息，包括时间戳和是否压缩的标志。
// 定义一个函数，用于读取内核消息头部信息
static int ramoops_read_kmsg_hdr(char *buffer, struct timespec64 *time,
				  bool *compressed)
{
	char data_type;  // 用于存储数据类型字符
	int header_length = 0;  // 用于存储头部长度

	// 尝试从buffer中按照带有压缩标记的格式读取时间和数据类型
	if (sscanf(buffer, RAMOOPS_KERNMSG_HDR "%lld.%lu-%c\n%n",
		   (time64_t *)&time->tv_sec, &time->tv_nsec, &data_type,
		   &header_length) == 3) {
		time->tv_nsec *= 1000;	// 将纳秒部分转换成合适的时间单位
		if (data_type == 'C')
			*compressed = true;	// 如果数据类型为'C'，设置压缩标志为真
		else
			*compressed = false;	// 否则设置压缩标志为假
	} else if (sscanf(buffer, RAMOOPS_KERNMSG_HDR "%lld.%lu\n%n",
			  (time64_t *)&time->tv_sec, &time->tv_nsec,
			  &header_length) == 2) {
		// 如果上面的格式匹配失败，尝试不带压缩标记的格式读取时间
		time->tv_nsec *= 1000;	// 同样将纳秒部分转换成合适的时间单位
		*compressed = false;	// 设置压缩标志为假
	} else {
		time->tv_sec = 0;	// 如果都不匹配，将时间设置为0
		time->tv_nsec = 0;
		*compressed = false;	// 压缩标志设置为假
	}
	return header_length;	// 返回读取到的头部长度
}

// 用于检查一个持久性RAM区域（persistent_ram_zone）是否有效，即该区域是否存在数据以及是否可以正常访问
// 定义一个函数，用于检查持久性RAM区域是否有效
static bool prz_ok(struct persistent_ram_zone *prz)
{
	// 返回一个布尔值，首先检查prz指针是否非空（!!prz）
	// 然后检查调用persistent_ram_old_size(prz)得到的旧数据大小
	// 加上调用persistent_ram_ecc_string(prz, NULL, 0)尝试获取ECC数据字符串长度（实际上并不获取，因为传递的是NULL和0）
	// 使用!!确保返回结果为布尔类型，如果总和为非零，则认为该RAM区域是有效的
	return !!prz && !!(persistent_ram_old_size(prz) +
			   persistent_ram_ecc_string(prz, NULL, 0));
}

// 定义了一个函数，用于从ramoops持久性内存区域中读取日志记录，处理多种日志类型如DMESG、控制台、用户空间消息和ftrace。
static ssize_t ramoops_pstore_read(struct pstore_record *record)
{
	ssize_t size = 0;  // 初始化读取的数据大小为0
	struct ramoops_context *cxt = record->psi->data;  // 获取ramoops上下文
	struct persistent_ram_zone *prz = NULL;  // 初始化持久性RAM区域的指针
	int header_length = 0;  // 初始化日志头部长度
	bool free_prz = false;  // 标记是否需要释放prz指针

	/*
	 * Ramoops headers provide time stamps for PSTORE_TYPE_DMESG, but
	 * PSTORE_TYPE_CONSOLE and PSTORE_TYPE_FTRACE don't currently have
	 * valid time stamps, so it is initialized to zero.
	 */
	/*
	 * Ramoops的头部为PSTORE_TYPE_DMESG类型提供时间戳，但PSTORE_TYPE_CONSOLE和
	 * PSTORE_TYPE_FTRACE目前没有有效时间戳，因此将其初始化为零。
	 */
	// 初始化时间戳为0，因为除了DMESG类型外，其他类型可能没有有效的时间戳
	record->time.tv_sec = 0;
	record->time.tv_nsec = 0;
	record->compressed = false;	// 初始化压缩标志为假

	/* Find the next valid persistent_ram_zone for DMESG */
	// 查找下一个有效的DMESG持久性RAM区域
	// 循环直到读取计数达到最大转储计数或找到一个有效的区域
	while (cxt->dump_read_cnt < cxt->max_dump_cnt && !prz) {
		// 获取下一个持久性RAM区域，cxt->dprzs是持久性RAM区域的数组，cxt->dump_read_cnt是当前读取计数，record是当前的存储记录
		prz = ramoops_get_next_prz(cxt->dprzs, cxt->dump_read_cnt++,
					   record);
		if (!prz_ok(prz))	// 检查获取的RAM区域是否有效
			continue;	// 如果区域无效，继续查找
		// 读取该区域中的旧数据的头部信息，并记录时间戳和是否压缩的状态
		// header_length将返回头部信息的长度，如果头部信息无效，则为0
		header_length = ramoops_read_kmsg_hdr(persistent_ram_old(prz),
						      &record->time,
						      &record->compressed);
		/* Clear and skip this DMESG record if it has no valid header */
		// 如果没有有效的头部，清除并跳过这条记录
		if (!header_length) {
			persistent_ram_free_old(prz);	// 释放该区域中的旧数据
			persistent_ram_zap(prz);	// 清除该区域中的所有数据，重置状态
			prz = NULL;			// 重置prz指针，继续查找下一个区域
		}
	}

	if (!prz_ok(prz) && !cxt->console_read_cnt++)	// 如果未找到有效的DMESG且未读取控制台日志
		// 获取控制台日志区域
		prz = ramoops_get_next_prz(&cxt->cprz, 0 /* single */, record);

	if (!prz_ok(prz) && !cxt->pmsg_read_cnt++)	// 如果以上日志区域仍无效且未读取PMSG日志
		// 获取PMSG日志区域
		prz = ramoops_get_next_prz(&cxt->mprz, 0 /* single */, record);

	/* ftrace is last since it may want to dynamically allocate memory. */
	// Ftrace记录是最后获取，因为可能需要动态分配内存
	// 如果当前持久性RAM区域不可用
	if (!prz_ok(prz)) {
		// 检查是否为每CPU记录且未处理
		if (!(cxt->flags & RAMOOPS_FLAG_FTRACE_PER_CPU) &&
		    !cxt->ftrace_read_cnt++) {	// 如果Ftrace记录未被处理
			// 获取下一个Ftrace记录
			prz = ramoops_get_next_prz(cxt->fprzs, 0 /* single */,
						   record);
		} else {
			/*
			 * Build a new dummy record which combines all the
			 * per-cpu records including metadata and ecc info.
			 */
			// 构建一个新的虚拟记录，该记录合并所有CPU的记录，包括元数据和ECC信息
			struct persistent_ram_zone *tmp_prz, *prz_next;
			
			// 为新的RAM区域结构体分配内存
			tmp_prz = kzalloc(sizeof(struct persistent_ram_zone),
					  GFP_KERNEL);	// 分配一个新的RAM区域结构体
			if (!tmp_prz)
				return -ENOMEM;	// 如果内存分配失败，返回错误
			prz = tmp_prz;
			free_prz = true;	// 设置标志以便之后释放该临时区域

			// 循环处理所有Ftrace记录
			while (cxt->ftrace_read_cnt < cxt->max_ftrace_cnt) {
				// 获取下一个Ftrace记录
				prz_next = ramoops_get_next_prz(cxt->fprzs,
						cxt->ftrace_read_cnt++, record);

				if (!prz_ok(prz_next))	// 如果记录不可用，跳过
					continue;	// 如果获取的区域无效，继续尝试

				// 合并ECC信息、修正的字节数及坏块数量
				tmp_prz->ecc_info = prz_next->ecc_info;	// 合并ECC信息
				tmp_prz->corrected_bytes +=
						prz_next->corrected_bytes;	// 合并修正的字节数
				tmp_prz->bad_blocks += prz_next->bad_blocks;	// 合并坏块数量

				 // 合并日志数据
				size = pstore_ftrace_combine_log(	// 合并ftrace日志
						&tmp_prz->old_log,
						&tmp_prz->old_log_size,
						prz_next->old_log,
						prz_next->old_log_size);
				// 如果合并有返回值（非零），表示有有效数据
				if (size)	// 如果合并成功，跳转至输出
					goto out;
			}
			record->id = 0;	// 设置记录ID
		}
	}

	if (!prz_ok(prz)) {	// 如果没有有效的区域
		size = 0;	// 设置大小为0
		goto out;	// 跳转至输出
	}

	// 如果有有效的持久性RAM区域，计算有效数据大小，即持久区域存储的旧数据大小减去头部长度
	size = persistent_ram_old_size(prz) - header_length;	// 计算有效数据的大小

	/* ECC correction notice */
	// 获取ECC修正通知的大小，该函数调用不改变原有数据，只计算ECC字符串的长度
	record->ecc_notice_size = persistent_ram_ecc_string(prz, NULL, 0);	// 获取ECC校正通知的大小

	// 为存储有效数据及ECC通知分配内存，加1保证有足够的空间存储字符串结束符
	record->buf = kmalloc(size + record->ecc_notice_size + 1, GFP_KERNEL);	// 为数据及ECC通知分配内存
	if (record->buf == NULL) {	// 如果内存分配失败
		size = -ENOMEM;		// 设置错误码
		goto out;		// 跳转至输出
	}

	// 将有效数据从持久性RAM区域复制到新分配的缓冲区
	memcpy(record->buf, (char *)persistent_ram_old(prz) + header_length,
	       size);	// 将有效数据复制到缓冲区

	// 在数据后附加ECC修正通知
	persistent_ram_ecc_string(prz, record->buf + size,
				  record->ecc_notice_size + 1);	// 将ECC通知追加到数据后

out:
	if (free_prz) {	// 如果设置了释放prz的标志（通常是合并Ftrace日志时分配的临时区域）
		kfree(prz->old_log);	// 释放持久性RAM区域中的旧日志数据
		kfree(prz);		// 释放持久性RAM区域结构体本身
	}

	return size;	// 返回读取的数据大小或错误代码
}

// 定义了一个函数，用于将内核消息（kmsg）的头信息写入到指定的持久性RAM区域中。
// 定义一个函数，用于写入内核消息头部信息到持久性RAM区域
/*
 * 这个函数主要用于记录内核崩溃时的日志信息，头信息包括崩溃发生的时间（秒和微秒）以及消息是否被压缩的标志。
 * 这些信息被预先格式化成一个字符串，然后写入持久性内存区域中，这样在系统重新启动后仍能访问这些崩溃日志。
 */
static size_t ramoops_write_kmsg_hdr(struct persistent_ram_zone *prz,
				     struct pstore_record *record)
{
	// 定义一个字符数组hdr，足够存储格式化的时间戳和压缩标志
	char hdr[36]; /* "===="(4), %lld(20), "."(1), %06lu(6), "-%c\n"(3) */
	size_t len;

	// 使用scnprintf函数格式化头信息到hdr数组，包括时间戳和压缩标志
	// RAMOOPS_KERNMSG_HDR是头部开始标记，通常是"===="
	// %lld.%06lu-%c\n 是格式化字符串，表示长整型的秒数，微秒数，和一个字符（'C'表示压缩，'D'表示未压缩）
	len = scnprintf(hdr, sizeof(hdr),
		RAMOOPS_KERNMSG_HDR "%lld.%06lu-%c\n",
		(time64_t)record->time.tv_sec,
		record->time.tv_nsec / 1000,
		record->compressed ? 'C' : 'D');
	persistent_ram_write(prz, hdr, len);	// 将格式化的头信息写入持久性RAM区域

	return len;	// 返回写入的长度
}

// 实现了一个函数，用于将不同类型的记录（如控制台、Ftrace、PMSG、DMESG）写入持久性内存。这是pstore框架在处理崩溃时收集日志数据的一部分。
// 定义一个不跟踪的静态函数，用于写入日志记录到持久性RAM区域
/*
 * 这段代码详细地实现了将不同类型的记录（如控制台、Ftrace、PMSG、DMESG）写入持久性内存的逻辑，
 * 包括错误处理和内存管理，确保系统崩溃时的关键信息能够被可靠地记录并在重启后进行回溯分析。
 */
static int notrace ramoops_pstore_write(struct pstore_record *record)
{
	struct ramoops_context *cxt = record->psi->data;	// 从pstore记录中获取ramoops上下文
	struct persistent_ram_zone *prz;	// 声明一个持久性RAM区域变量
	size_t size, hlen;	// 声明变量用于存储记录的大小和头部长度

	// 如果记录类型为控制台
	if (record->type == PSTORE_TYPE_CONSOLE) {
		if (!cxt->cprz)
			return -ENOMEM;	 // 如果控制台持久性RAM区不存在，返回内存不足错误
		// 将记录写入控制台的持久性RAM区
		persistent_ram_write(cxt->cprz, record->buf, record->size);
		return 0;	// 写入成功，返回0
	} else if (record->type == PSTORE_TYPE_FTRACE) {	// 如果记录类型为Ftrace
		int zonenum;	// 声明一个区域编号变量

		if (!cxt->fprzs)
			return -ENOMEM;	// 如果Ftrace持久性RAM区数组不存在，返回内存不足错误
		/*
		 * Choose zone by if we're using per-cpu buffers.
		 */
		// 根据是否使用每CPU缓冲区选择区域
		if (cxt->flags & RAMOOPS_FLAG_FTRACE_PER_CPU)
			zonenum = smp_processor_id();	// 如果设置了每CPU标志，选择当前CPU对应的区域编号
		else
			zonenum = 0;	// 否则使用第0区

		persistent_ram_write(cxt->fprzs[zonenum], record->buf,
				     record->size);	// 将记录写入指定的Ftrace持久性RAM区
		return 0;	// 写入成功，返回0
	} else if (record->type == PSTORE_TYPE_PMSG) {	// 如果记录类型为PMSG
		pr_warn_ratelimited("PMSG shouldn't call %s\n", __func__);	// 打印警告，表明PMSG不应该调用这个函数
		return -EINVAL;	// 返回无效参数错误
	}

	if (record->type != PSTORE_TYPE_DMESG)	// 如果记录类型不是DMESG，返回无效参数错误
		return -EINVAL;

	/*
	 * We could filter on record->reason here if we wanted to (which
	 * would duplicate what happened before the "max_reason" setting
	 * was added), but that would defeat the purpose of a system
	 * changing printk.always_kmsg_dump, so instead log everything that
	 * the kmsg dumper sends us, since it should be doing the filtering
	 * based on the combination of printk.always_kmsg_dump and our
	 * requested "max_reason".
	 */
	/*
	 * 如果需要，我们可以在这里根据record->reason进行过滤（这将复制添加“max_reason”设置之前的行为），
	 * 但这将违背系统更改printk.always_kmsg_dump的目的，
	 * 因此我们应该记录kmsg dumper发送给我们的所有内容，
	 * 因为它应该基于printk.always_kmsg_dump和我们请求的“max_reason”的组合进行过滤。
	 */

	/*
	 * Explicitly only take the first part of any new crash.
	 * If our buffer is larger than kmsg_bytes, this can never happen,
	 * and if our buffer is smaller than kmsg_bytes, we don't want the
	 * report split across multiple records.
	 */
	/*
	 * 明确只取任何新崩溃的第一部分。
	 * 如果我们的缓冲区大于kmsg_bytes，这种情况永远不会发生，
	 * 如果我们的缓冲区小于kmsg_bytes，我们不希望
	 * 报告分布在多个记录中。
	 */
	
	if (record->part != 1)	// 明确只取任何新崩溃的第一部分
		return -ENOSPC;	// 如果记录不是新崩溃的第一部分，返回没有空间错误

	if (!cxt->dprzs)
		return -ENOSPC;	// 如果DMESG持久性RAM区数组不存在，返回没有空间错误

	prz = cxt->dprzs[cxt->dump_write_cnt];	// 获取当前写入计数对应的持久性RAM区

	/*
	 * Since this is a new crash dump, we need to reset the buffer in
	 * case it still has an old dump present. Without this, the new dump
	 * will get appended, which would seriously confuse anything trying
	 * to check dump file contents. Specifically, ramoops_read_kmsg_hdr()
	 * expects to find a dump header in the beginning of buffer data, so
	 * we must to reset the buffer values, in order to ensure that the
	 * header will be written to the beginning of the buffer.
	 */
	/*
	 * 由于这是一个新的崩溃转储，我们需要重置缓冲区以清除可能存在的旧转储。
	 * 如果不这样做，新的转储将会被追加，这会严重混淆任何尝试
	 * 检查转储文件内容的操作。特别是，ramoops_read_kmsg_hdr()
	 * 期望在缓冲区数据的开始找到一个转储头部，因此我们必须
	 * 重置缓冲区值，以确保头部将被写入缓冲区的开始。
	 */
	// 由于这是一个新的崩溃转储，我们需要重置缓冲区以清除可能存在的旧转储
	persistent_ram_zap(prz);	// 重置持久性RAM区，以确保可以从头开始写入新的崩溃转储

	/* Build header and append record contents. */
	// 构建头部并追加记录内容
	// 写入kmsg头部，并获取头部长度
	hlen = ramoops_write_kmsg_hdr(prz, record);	// 构建头部信息并获取长度
	if (!hlen)
		return -ENOMEM;	// 如果头部长度为0，返回内存不足错误

	size = record->size;
	if (size + hlen > prz->buffer_size)
		size = prz->buffer_size - hlen;	// 计算可以写入的数据大小，确保不会超过持久性RAM区的容量
	persistent_ram_write(prz, record->buf, size);	// 将数据写入持久性RAM区

	cxt->dump_write_cnt = (cxt->dump_write_cnt + 1) % cxt->max_dump_cnt;	// 更新写入计数，循环使用持久性RAM区

	return 0;	// 写入成功，返回0
}

// 定义了一个函数，专门用于处理从用户空间写入数据到指定的持久性内存区域。这里的代码专注于处理PSTORE_TYPE_PMSG类型的记录。
// 定义一个静态函数，不会被追踪(tracing)。此函数用于将来自用户空间的数据写入pstore记录。
static int notrace ramoops_pstore_write_user(struct pstore_record *record,
					     const char __user *buf)
{
	// 检查记录的类型是否为PMSG（即用于存储用户空间的消息）
	if (record->type == PSTORE_TYPE_PMSG) {
		// 从pstore记录中获取ramoops上下文，该上下文包含所有操作的必要信息
		struct ramoops_context *cxt = record->psi->data;

		// 如果指定的PMSG持久性内存区域不存在，则返回内存不足错误
		if (!cxt->mprz)
			return -ENOMEM;
		// 调用persistent_ram_write_user函数，将用户空间的数据写入PMSG持久性内存区域并返回操作的结果
		return persistent_ram_write_user(cxt->mprz, buf, record->size);
	}

	return -EINVAL;	// 如果记录类型不是PMSG，返回无效参数错误
}

// 定义了一个函数，用于清除特定类型的记录在持久性RAM区域中的数据。
// 定义一个静态函数，用于从持久性内存区域中擦除pstore记录
static int ramoops_pstore_erase(struct pstore_record *record)
{
	// 从pstore记录获取ramoops上下文，该上下文包含管理持久性内存的所有必要信息
	struct ramoops_context *cxt = record->psi->data;
	struct persistent_ram_zone *prz;	// 声明一个指向持久性RAM区域的指针

	switch (record->type) {	// 根据记录的类型选择操作
	case PSTORE_TYPE_DMESG:	// 如果记录类型是DMESG（内核消息日志）
		if (record->id >= cxt->max_dump_cnt)	// 如果给定的记录ID超出了允许的最大数量，返回无效参数错误
			return -EINVAL;
		prz = cxt->dprzs[record->id];	// 获取对应的持久性RAM区域
		break;
	case PSTORE_TYPE_CONSOLE:	// 如果记录类型是控制台日志
		prz = cxt->cprz;	// 获取控制台的持久性RAM区域
		break;
	case PSTORE_TYPE_FTRACE:	// 如果记录类型是Ftrace（函数跟踪日志）
		if (record->id >= cxt->max_ftrace_cnt)
			return -EINVAL;	// 如果给定的记录ID超出了允许的最大数量，返回无效参数错误
		prz = cxt->fprzs[record->id];	// 获取对应的持久性RAM区域
		break;
	case PSTORE_TYPE_PMSG:	// 如果记录类型是PMSG（用户空间消息）
		prz = cxt->mprz;	// 获取PMSG的持久性RAM区域
		break;
	default:	// 如果记录类型不是以上任何一种
		return -EINVAL;	// 返回无效参数错误
	}

	persistent_ram_free_old(prz);	// 释放prz中的旧数据，如果有的话
	persistent_ram_zap(prz);	// 完全清除prz区域的内容，重置其状态

	return 0;	// 返回0表示操作成功完成
}

// 初始化了一个名为oops_cxt的ramoops_context结构体实例，用于配置pstore（持久性存储）模块的操作函数。
// 定义并初始化一个静态的ramoops_context结构体实例，名为oops_cxt
static struct ramoops_context oops_cxt = {
	// 初始化pstore子结构
	.pstore = {
		.owner	= THIS_MODULE,	// 设置模块所有者为当前模块
		.name	= "ramoops",	// 设置模块名称为"ramoops"
		.open	= ramoops_pstore_open,	// 设置打开函数为ramoops_pstore_open，负责打开存储区域
		.read	= ramoops_pstore_read,	// 设置读取函数为ramoops_pstore_read，负责读取存储区域的数据
		.write	= ramoops_pstore_write,	// 设置写入函数为ramoops_pstore_write，负责写入数据到存储区域
		.write_user	= ramoops_pstore_write_user,	// 设置用户空间写入函数为ramoops_pstore_write_user，允许从用户空间直接写入数据
		.erase	= ramoops_pstore_erase,	// 设置擦除函数为ramoops_pstore_erase，负责擦除存储区域的数据
	},
};

// 定义了一个函数，用于释放ramoops_context中所有持久性RAM区域（PRZ）的资源。这些区域包括崩溃日志（dump PRZs）和函数追踪日志（ftrace PRZs）。
// 定义一个静态函数，用于释放ramoops上下文中的所有持久性RAM区域资源
static void ramoops_free_przs(struct ramoops_context *cxt)
{
	int i;	// 声明循环变量

	/* Free dump PRZs */
	/* 释放崩溃日志持久性RAM区域 */
	// 如果存储崩溃日志的持久性RAM区域数组存在
	if (cxt->dprzs) {
		// 遍历所有崩溃日志持久性RAM区域
		for (i = 0; i < cxt->max_dump_cnt; i++)
			persistent_ram_free(cxt->dprzs[i]);	// 释放每一个持久性RAM区域

		// 释放持久性RAM区域数组本身
		kfree(cxt->dprzs);
		cxt->max_dump_cnt = 0;	// 将最大崩溃日志数量重置为0
	}

	/* Free ftrace PRZs */
	/* 释放函数追踪日志持久性RAM区域 */
	// 如果存储函数追踪日志的持久性RAM区域数组存在
	if (cxt->fprzs) {
		// 遍历所有函数追踪日志持久性RAM区域
		for (i = 0; i < cxt->max_ftrace_cnt; i++)
			// 释放每一个持久性RAM区域
			persistent_ram_free(cxt->fprzs[i]);
		kfree(cxt->fprzs);	// 释放持久性RAM区域数组本身
		cxt->max_ftrace_cnt = 0;	// 将最大函数追踪日志数量重置为0
	}
}

// 定义了一个名为的函数，其功能是初始化一个持久性RAM区域数组。
// 定义一个静态函数，用于初始化一组持久性RAM区域
static int ramoops_init_przs(const char *name,
			     struct device *dev, struct ramoops_context *cxt,
			     struct persistent_ram_zone ***przs,
			     phys_addr_t *paddr, size_t mem_sz,
			     ssize_t record_size,
			     unsigned int *cnt, u32 sig, u32 flags)
{
	int err = -ENOMEM;	// 初始化错误代码为内存不足
	int i;			// 循环变量
	size_t zone_sz;		// 每个区域的大小
	struct persistent_ram_zone **prz_ar;

	/* Allocate nothing for 0 mem_sz or 0 record_size. */
	/* 如果内存大小或记录大小为0，则不分配任何内容。 */
	if (mem_sz == 0 || record_size == 0) {
		*cnt = 0;	// 设置计数为0
		return 0;	// 直接返回0
	}

	/*
	 * If we have a negative record size, calculate it based on
	 * mem_sz / *cnt. If we have a positive record size, calculate
	 * cnt from mem_sz / record_size.
	 */
	/*
	 * 如果记录大小为负，根据 mem_sz / *cnt 计算它。
	 * 如果记录大小为正，根据 mem_sz / record_size 计算 cnt。
	 */
	// 如果记录大小为负
	if (record_size < 0) {
		if (*cnt == 0)
			return 0;	// 如果计数为0，则直接返回0
		record_size = mem_sz / *cnt;	// 根据内存大小和记录计数计算记录大小
		if (record_size == 0) {	// 如果计算后的记录大小为0
			dev_err(dev, "%s record size == 0 (%zu / %u)\n",
				name, mem_sz, *cnt);	// 打印错误信息
			goto fail;	// 跳转到失败处理
		}
	} else {	// 如果记录大小为正
		*cnt = mem_sz / record_size;	// 根据内存大小和记录大小计算记录区域计数
		if (*cnt == 0) {	// 如果计算后的计数为0
			dev_err(dev, "%s record count == 0 (%zu / %zu)\n",
				name, mem_sz, record_size);	// 打印错误信息
			goto fail;	// 跳转到失败处理
		}
	}

	// 如果内存地址加内存大小超出了上下文中指定的物理地址范围
	if (*paddr + mem_sz - cxt->phys_addr > cxt->size) {
		dev_err(dev, "no room for %s mem region (0x%zx@0x%llx) in (0x%lx@0x%llx)\n",
			name,
			mem_sz, (unsigned long long)*paddr,
			cxt->size, (unsigned long long)cxt->phys_addr);	// 打印错误信息
		goto fail;	// 跳转到失败处理
	}

	zone_sz = mem_sz / *cnt;	// 计算每个区域的大小
	if (!zone_sz) {	// 如果区域大小为0
		dev_err(dev, "%s zone size == 0\n", name);	// 打印错误信息
		goto fail;	// 跳转到失败处理
	}

	prz_ar = kcalloc(*cnt, sizeof(**przs), GFP_KERNEL);	// 为区域数组分配内存
	if (!prz_ar)
		goto fail;	// 如果内存分配失败，跳转到失败处理

	// 遍历每个区域
	for (i = 0; i < *cnt; i++) {
		char *label;

		// 生成区域标签
		if (*cnt == 1)
			label = kasprintf(GFP_KERNEL, "ramoops:%s", name);	// 为单个区域生成标签
		else
			label = kasprintf(GFP_KERNEL, "ramoops:%s(%d/%d)",	// 为多个区域生成标签
					  name, i, *cnt - 1);
		prz_ar[i] = persistent_ram_new(*paddr, zone_sz, sig,
					       &cxt->ecc_info,
					       cxt->memtype, flags, label);	// 初始化每个持久性RAM区域
		kfree(label);	// 释放标签内存
		if (IS_ERR(prz_ar[i])) {	// 如果初始化失败
			err = PTR_ERR(prz_ar[i]);	// 获取错误代码
			dev_err(dev, "failed to request %s mem region (0x%zx@0x%llx): %d\n",
				name, record_size,
				(unsigned long long)*paddr, err);	// 打印错误信息

			// 释放已初始化的区域
			while (i > 0) {
				i--;
				persistent_ram_free(prz_ar[i]);
			}
			kfree(prz_ar);	// 释放区域数组内存
			goto fail;	// 跳转到失败处理
		}
		*paddr += zone_sz;	// 更新物理地址
		prz_ar[i]->type = pstore_name_to_type(name);	// 设置区域类型
	}

	*przs = prz_ar;	// 设置返回的区域数组
	return 0;

fail:
	*cnt = 0;	// 设置计数为0
	return err;	// 返回错误代码
}

// 定义了一个函数ramoops_init_prz，用于初始化单个持久性RAM区域（PRZ）。
// 定义一个静态函数，用于初始化单个持久性RAM区域
static int ramoops_init_prz(const char *name,
			    struct device *dev, struct ramoops_context *cxt,
			    struct persistent_ram_zone **prz,
			    phys_addr_t *paddr, size_t sz, u32 sig)
{
	char *label;	// 声明一个字符指针用于存储区域标签

	if (!sz)	// 如果传入的区域大小为0，则直接返回成功
		return 0;

	// 如果新区域的地址和大小超出了ramoops上下文定义的物理地址范围，打印错误并返回内存不足错误
	if (*paddr + sz - cxt->phys_addr > cxt->size) {
		dev_err(dev, "no room for %s mem region (0x%zx@0x%llx) in (0x%lx@0x%llx)\n",
			name, sz, (unsigned long long)*paddr,
			cxt->size, (unsigned long long)cxt->phys_addr);
		return -ENOMEM;
	}

	// 分配并格式化区域标签，如"ramoops:kernel_log"
	label = kasprintf(GFP_KERNEL, "ramoops:%s", name);
	// 初始化持久性RAM区域，分配内存并设置其属性
	*prz = persistent_ram_new(*paddr, sz, sig, &cxt->ecc_info,
				  cxt->memtype, PRZ_FLAG_ZAP_OLD, label);
	kfree(label);	// 释放标签内存
	// 如果初始化持久性RAM区域失败
	if (IS_ERR(*prz)) {
		int err = PTR_ERR(*prz);	// 获取错误代码

		dev_err(dev, "failed to request %s mem region (0x%zx@0x%llx): %d\n",
			name, sz, (unsigned long long)*paddr, err);	// 打印错误信息
		return err;	// 返回错误代码
	}

	*paddr += sz;	// 更新物理地址，为下一个区域做准备
	(*prz)->type = pstore_name_to_type(name);	// 设置持久性RAM区域的类型，转换字符串名称到枚举类型

	return 0;	// 返回成功
}

/* Read a u32 from a dt property and make sure it's safe for an int. */
/* 从设备树属性中读取一个u32值，并确保其安全适用于int类型。 */
// 定义了一个名为ramoops_parse_dt_u32的函数，用于从设备树中读取一个u32类型的属性值，并确保其值在int类型的安全范围内。
/*
 * 这个函数的作用是安全地从设备树中读取u32类型的配置属性。如果指定的属性不存在，
 * 则使用默认值。函数还检查属性值是否超过了int类型的最大值，以防止潜在的溢出问题。
 */
static int ramoops_parse_dt_u32(struct platform_device *pdev,
				const char *propname,
				u32 default_value, u32 *value)
{
	u32 val32 = 0;	// 定义一个u32变量，初始化为0
	int ret;	// 用于存储返回值

	// 从设备树中读取名为propname的属性到val32中
	ret = of_property_read_u32(pdev->dev.of_node, propname, &val32);
	if (ret == -EINVAL) {
		/* field is missing, use default value. */
		/* 属性字段缺失，使用默认值。 */
		val32 = default_value;	// 如果属性缺失，使用传入的默认值
	} else if (ret < 0) {	// 如果读取属性失败
		dev_err(&pdev->dev, "failed to parse property %s: %d\n",
			propname, ret);	// 输出错误日志
		return ret;	// 返回错误代码
	}

	/* Sanity check our results. */
	/* 对结果进行合理性检查。 */
	// 如果val32的值超过int类型的最大值
	if (val32 > INT_MAX) {
		dev_err(&pdev->dev, "%s %u > INT_MAX\n", propname, val32);	// 输出错误日志
		return -EOVERFLOW;	// 返回溢出错误
	}

	*value = val32;	// 将读取的值赋给value指针指向的变量
	return 0;	// 返回0表示成功
}

// 定义了一个名为ramoops_parse_dt的函数，用于从设备树中解析ramoops模块所需的参数。这些参数包括内存大小、地址、记录类型等。
// 定义一个函数，用于解析设备树中的配置参数并设置到ramoops_platform_data结构体中
static int ramoops_parse_dt(struct platform_device *pdev,
			    struct ramoops_platform_data *pdata)
{
	struct device_node *of_node = pdev->dev.of_node;	// 获取设备节点
	struct device_node *parent_node;	// 声明一个用于存储父节点的变量
	// 用于获取内存资源
	struct resource *res;	// 声明一个资源结构体指针
	u32 value;	// 用于存储从设备树中解析出的临时u32类型的值
	int ret;	// 用于存储返回值

	dev_dbg(&pdev->dev, "using Device Tree\n");	// 在调试输出中标明正在使用设备树进行配置

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);	// 从设备获取第一个内存资源
	if (!res) {
		// 如果没有找到资源，输出错误信息并返回无效参数错误
		dev_err(&pdev->dev,
			"failed to locate DT /reserved-memory resource\n");
		return -EINVAL;
	}

	pdata->mem_size = resource_size(res);	// 获取并设置内存资源的大小
	pdata->mem_address = res->start;	// 获取并设置内存资源的起始地址

	/*
	 * Setting "unbuffered" is deprecated and will be ignored if
	 * "mem_type" is also specified.
	 */
	/*
	 * 设置“unbuffered”已弃用，如果同时指定了“mem_type”，将被忽略。
	 */
	// 从设备树中读取"unbuffered"属性，但该属性已弃用
	// 读取是否未缓冲的配置（已废弃），并存储到pdata中
	pdata->mem_type = of_property_read_bool(of_node, "unbuffered");
	/*
	 * Setting "no-dump-oops" is deprecated and will be ignored if
	 * "max_reason" is also specified.
	 */
	/*
	 * 设置“no-dump-oops”已弃用，如果同时指定了“max_reason”，将被忽略。
	 */
	// 如果设置了"no-dump-oops"，设置最大原因为panic，否则为oops
	// 如果设置了不记录oops（已废弃），将最大记录原因设为PANIC
	if (of_property_read_bool(of_node, "no-dump-oops"))
		// 如果设备树中设置了"no-dump-oops"，则将max_reason设置为PANIC
		pdata->max_reason = KMSG_DUMP_PANIC;
	else
		// 否则设为OOPS
		pdata->max_reason = KMSG_DUMP_OOPS;

// 定义一个宏，用于解析u32类型的值并设置到相应的字段，如果解析失败则返回错误代码
#define parse_u32(name, field, default_value) {				\
		ret = ramoops_parse_dt_u32(pdev, name, default_value,	\
					    &value);			\
		if (ret < 0)						\
			return ret;					\
		field = value;						\
	}

	// 使用宏依次解析并设置各参数
	parse_u32("mem-type", pdata->mem_type, pdata->mem_type);
	parse_u32("record-size", pdata->record_size, 0);
	parse_u32("console-size", pdata->console_size, 0);
	parse_u32("ftrace-size", pdata->ftrace_size, 0);
	parse_u32("pmsg-size", pdata->pmsg_size, 0);
	parse_u32("ecc-size", pdata->ecc_info.ecc_size, 0);
	parse_u32("flags", pdata->flags, 0);
	parse_u32("max-reason", pdata->max_reason, pdata->max_reason);

// 取消宏定义
#undef parse_u32

	/*
	 * Some old Chromebooks relied on the kernel setting the
	 * console_size and pmsg_size to the record size since that's
	 * what the downstream kernel did.  These same Chromebooks had
	 * "ramoops" straight under the root node which isn't
	 * according to the current upstream bindings (though it was
	 * arguably acceptable under a prior version of the bindings).
	 * Let's make those old Chromebooks work by detecting that
	 * we're not a child of "reserved-memory" and mimicking the
	 * expected behavior.
	 */
	/*
	 * 一些旧Chromebooks依赖于内核将控制台大小和pmsg大小设置为记录大小，
	 * 因为这是下游内核所做的。这些相同的Chromebooks将“ramoops”直接放在根节点下，
	 * 这并不符合当前的上游绑定（尽管在之前版本的绑定中这可能是可接受的）。
	 * 让我们通过检测我们是否不是“reserved-memory”的子节点并模仿预期的行为，
	 * 使这些旧Chromebooks能够正常工作。
	 */
	/*
	 * 一些旧的Chromebooks依赖于内核将控制台大小和pmsg大小设置为记录大小，这是旧内核的做法。
	 * 这些Chromebooks将"ramoops"直接放在根节点下，这与当前上游的绑定不符（虽然在之前的绑定版本中可能是可接受的）。
	 * 我们通过检测我们是否不是"reserved-memory"的子节点并模拟预期的行为来使这些旧Chromebooks正常工作。
	 */
	parent_node = of_get_parent(of_node);	// 获取父节点
	// 如果不是"reserved-memory"的子节点，且相关尺寸未设置，则将其设置为记录大小
	if (!of_node_name_eq(parent_node, "reserved-memory") &&
	    !pdata->console_size && !pdata->ftrace_size &&
	    !pdata->pmsg_size && !pdata->ecc_info.ecc_size) {	// 如果不是reserved-memory的子节点，并且相关尺寸未设置
	    	// 将控制台大小和pmsg大小设置为记录大小，以模拟旧Chromebooks的预期行为
		pdata->console_size = pdata->record_size;
		pdata->pmsg_size = pdata->record_size;
	}
	of_node_put(parent_node);	// 释放父节点引用

	return 0;	// 返回成功
}

// 实现了ramoops_probe函数，它是Linux内核中ramoops模块的初始化函数，负责从设备树解析配置数据，初始化内存资源，并注册pstore接口
/*
 * ramoops_probe函数负责在平台设备初始化时进行各项配置的解析和资源的申请。它首先检查是否已
 * 经有实例化的ramoops上下文，如果有则直接失败。然后根据是否有提供的平台数据，决定是直接使用
 * 还是从设备树中解析。之后验证了获取的配置数据是否合理，包括内存大小和记录大小等。如果配置数据合法，
 * 它会依次初始化用于存储核心转储、控制台日志、Ftrace日志和PMSG日志的内存区域。每一步初始化都有可能
 * 失败并进行清理。最后，它尝试注册pstore接口，成功后更新相关的模块参数变量。如果在任何步骤中遇到错误，
 * 它将执行清理工作并返回错误代码。
 */
static int ramoops_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;  // 获取设备指针
	struct ramoops_platform_data *pdata = dev->platform_data;  // 获取平台数据
	struct ramoops_platform_data pdata_local;  // 定义一个本地的平台数据结构
	struct ramoops_context *cxt = &oops_cxt;  // 获取全局的ramoops上下文
	size_t dump_mem_sz;  // 用于计算崩溃内存区域大小
	phys_addr_t paddr;  // 物理地址变量，用于跟踪内存分配位置
	int err = -EINVAL;  // 初始化错误码为无效参数

	/*
	 * Only a single ramoops area allowed at a time, so fail extra
	 * probes.
	 */
	// 只允许单一的ramoops区域，如果已经初始化则失败
	// 检查是否已经有ramoops上下文被初始化，如果已初始化则打印错误并跳转到失败处理
	if (cxt->max_dump_cnt) {
		pr_err("already initialized\n");	// 如果已经初始化，则输出错误信息
		goto fail_out;	// 跳转到失败处理代码
	}

	// 检查设备是否使用设备树，且当前没有有效的平台数据，则使用局部变量作为平台数据，并初始化
	if (dev_of_node(dev) && !pdata) {
		pdata = &pdata_local;
		memset(pdata, 0, sizeof(*pdata));	// 初始化本地平台数据结构

		err = ramoops_parse_dt(pdev, pdata);	// 从设备树中解析配置信息
		if (err < 0)
			goto fail_out;	// 如果解析失败，则跳转到失败处理代码
	}

	/* Make sure we didn't get bogus platform data pointer. */
	// 确保获取到的平台数据指针不为空
	if (!pdata) {
		// 如果未获取到有效的平台数据，输出错误并处理失败
		pr_err("NULL platform data\n");	// 如果平台数据为空，输出错误信息
		err = -EINVAL;	// 设置错误代码为无效参数
		goto fail_out;	// 跳转到失败处理代码
	}

	// 确保内存大小和至少一个记录区域大小不为零
	// 确保内存大小和记录大小非零，否则输出错误并处理失败
	if (!pdata->mem_size || (!pdata->record_size && !pdata->console_size &&
			!pdata->ftrace_size && !pdata->pmsg_size)) {
		pr_err("The memory size and the record/console size must be "
			"non-zero\n");	// 如果关键配置项为零，输出错误信息
		err = -EINVAL;	// 设置错误代码为无效参数
		goto fail_out;	// 跳转到失败处理代码
	}

	// 确保记录大小、控制台大小、Ftrace大小和PMSG大小为2的幂，否则向下调整到最近的2的幂
	// 如果记录大小、控制台大小、Ftrace大小和PMSG大小不是2的幂，则调整为最接近的较小2的幂
	if (pdata->record_size && !is_power_of_2(pdata->record_size))
		pdata->record_size = rounddown_pow_of_two(pdata->record_size);
	if (pdata->console_size && !is_power_of_2(pdata->console_size))
		pdata->console_size = rounddown_pow_of_two(pdata->console_size);
	if (pdata->ftrace_size && !is_power_of_2(pdata->ftrace_size))
		pdata->ftrace_size = rounddown_pow_of_two(pdata->ftrace_size);
	if (pdata->pmsg_size && !is_power_of_2(pdata->pmsg_size))
		pdata->pmsg_size = rounddown_pow_of_two(pdata->pmsg_size);

	// 设置 ramoops 上下文中的各种内存大小和配置参数
	cxt->size = pdata->mem_size;  // 设置总内存大小
	cxt->phys_addr = pdata->mem_address;  // 设置物理起始地址
	cxt->memtype = pdata->mem_type;  // 设置内存类型
	cxt->record_size = pdata->record_size;  // 设置记录大小
	cxt->console_size = pdata->console_size;  // 设置控制台日志大小
	cxt->ftrace_size = pdata->ftrace_size;  // 设置 ftrace 日志大小
	cxt->pmsg_size = pdata->pmsg_size;  // 设置 pmsg 日志大小
	cxt->flags = pdata->flags;  // 设置标志位
	cxt->ecc_info = pdata->ecc_info;  // 设置 ECC 相关信息

	paddr = cxt->phys_addr;	// 计算剩余内存地址

	// 计算用于崩溃日志记录的内存大小
	dump_mem_sz = cxt->size - cxt->console_size - cxt->ftrace_size
			- cxt->pmsg_size;
	// 初始化Dmesg记录区域，初始化崩溃日志区域
	err = ramoops_init_przs("dmesg", dev, cxt, &cxt->dprzs, &paddr,
				dump_mem_sz, cxt->record_size,
				&cxt->max_dump_cnt, 0, 0);	// 初始化用于存储崩溃日志的内存区域
	if (err)	// 如果初始化失败，跳转到失败处理代码
		goto fail_out;

	// 初始化控制台记录区域
	err = ramoops_init_prz("console", dev, cxt, &cxt->cprz, &paddr,
			       cxt->console_size, 0);	// 初始化用于存储控制台日志的内存区域
	if (err)	// 如果初始化失败，跳转到失败处理代码
		goto fail_init_cprz;

	// 根据标志位决定Ftrace记录的数量
	cxt->max_ftrace_cnt = (cxt->flags & RAMOOPS_FLAG_FTRACE_PER_CPU)
				? nr_cpu_ids
				: 1;	// 根据是否为每个 CPU 配置一个 ftrace 区域来设置 ftrace 日志区域数量
	// 初始化Ftrace记录区域
	err = ramoops_init_przs("ftrace", dev, cxt, &cxt->fprzs, &paddr,
				cxt->ftrace_size, -1,
				&cxt->max_ftrace_cnt, LINUX_VERSION_CODE,
				(cxt->flags & RAMOOPS_FLAG_FTRACE_PER_CPU)
					? PRZ_FLAG_NO_LOCK : 0);
	if (err)	// 如果初始化失败，跳转到失败处理代码
		goto fail_init_fprz;

	// 初始化PMSG记录区域
	err = ramoops_init_prz("pmsg", dev, cxt, &cxt->mprz, &paddr,
				cxt->pmsg_size, 0);	// 初始化用于存储PMSG日志的内存区域
	if (err)	// 如果初始化失败，跳转到失败处理代码
		goto fail_init_mprz;

	cxt->pstore.data = cxt;	// 设置pstore数据指针为当前ramoops上下文
	/*
	 * Prepare frontend flags based on which areas are initialized.
	 * For ramoops_init_przs() cases, the "max count" variable tells
	 * if there are regions present. For ramoops_init_prz() cases,
	 * the single region size is how to check.
	 */
	/*
	 * 根据已初始化的区域准备前端标志。
	 * 对于 ramoops_init_przs() 的情况，"max count" 变量表明是否存在区域。
	 * 对于 ramoops_init_prz() 的情况，单个区域大小是检查的方法。
	 */
	// 根据已初始化的区域设置前端标志，这些标志将决定哪些类型的日志可以被存储
	cxt->pstore.flags = 0;	// 初始化 pstore 标志位
	if (cxt->max_dump_cnt) {
		cxt->pstore.flags |= PSTORE_FLAGS_DMESG;	// 如果有崩溃日志区域，则设置相应的标志
		cxt->pstore.max_reason = pdata->max_reason;	// 设置最大记录原因
	}
	if (cxt->console_size)
		cxt->pstore.flags |= PSTORE_FLAGS_CONSOLE;	// 如果有控制台日志区域，则设置控制台标志
	if (cxt->max_ftrace_cnt)
		cxt->pstore.flags |= PSTORE_FLAGS_FTRACE;	// 如果有 ftrace 日志区域，则设置 ftrace 标志
	if (cxt->pmsg_size)
		cxt->pstore.flags |= PSTORE_FLAGS_PMSG;		// 如果有 pmsg 日志区域，则设置 pmsg 标志

	/*
	 * Since bufsize is only used for dmesg crash dumps, it
	 * must match the size of the dprz record (after PRZ header
	 * and ECC bytes have been accounted for).
	 */
	 /*
	 * 由于缓冲区大小只用于崩溃日志，因此它必须与 dprz 记录的大小匹配（扣除 PRZ 头部和 ECC 字节后）。
	 */
	// 由于缓冲区大小只用于Dmesg崩溃日志，因此必须与DPRZ记录的大小匹配（减去PRZ头和ECC字节）
	if (cxt->pstore.flags & PSTORE_FLAGS_DMESG) {
		cxt->pstore.bufsize = cxt->dprzs[0]->buffer_size;	// 设置缓冲区大小为第一个崩溃日志区域的大小
		cxt->pstore.buf = kzalloc(cxt->pstore.bufsize, GFP_KERNEL);	// 为崩溃日志分配内存
		if (!cxt->pstore.buf) {
			pr_err("cannot allocate pstore crash dump buffer\n");	// 如果内存分配失败，输出错误信息
			err = -ENOMEM;	// 分配失败，设置错误码
			goto fail_clear;	// 跳转到错误处理
		}
	}

	err = pstore_register(&cxt->pstore);	// 注册pstore
	if (err) {
		pr_err("registering with pstore failed\n");	// 如果注册失败，输出错误信息
		goto fail_buf;	// 跳转到失败处理代码
	}

	/*
	 * Update the module parameter variables as well so they are visible
	 * through /sys/module/ramoops/parameters/
	 */
	/*
	 * 同时更新模块参数变量，使它们可以通过 /sys/module/ramoops/parameters/ 查看。
	 */
	// 更新模块参数变量，使它们通过/sys/module/ramoops/parameters/可见
	mem_size = pdata->mem_size;
	mem_address = pdata->mem_address;
	record_size = pdata->record_size;
	ramoops_max_reason = pdata->max_reason;
	ramoops_console_size = pdata->console_size;
	ramoops_pmsg_size = pdata->pmsg_size;
	ramoops_ftrace_size = pdata->ftrace_size;

	// 输出使用的内存和ECC大小信息
	pr_info("using 0x%lx@0x%llx, ecc: %d\n",
		cxt->size, (unsigned long long)cxt->phys_addr,
		cxt->ecc_info.ecc_size);

	return 0;	// 返回成功

fail_buf:	 // 处理分配缓冲区失败的情况
	kfree(cxt->pstore.buf);	// 释放缓冲区内存
fail_clear:
	cxt->pstore.bufsize = 0;	// 清除缓冲区大小
	persistent_ram_free(cxt->mprz);	// 释放PMSG区域内存
fail_init_mprz:	// 处理 pmsg 初始化失败的情况
fail_init_fprz:	// 处理 ftrace 初始化失败的情况
	persistent_ram_free(cxt->cprz);	// 释放控制台区域内存
fail_init_cprz:	// 处理控制台初始化失败的情况
	ramoops_free_przs(cxt);	// 释放所有PRZs内存
fail_out:
	return err;	// 返回错误码
}

// 定义了 ramoops_remove 函数，该函数是 ramoops 模块的清理函数，用于在模块移除时释放资源。
static int ramoops_remove(struct platform_device *pdev)
{
	struct ramoops_context *cxt = &oops_cxt;  // 获取全局的 ramoops 上下文

	pstore_unregister(&cxt->pstore);  // 取消注册 pstore

	kfree(cxt->pstore.buf);  // 释放为 pstore 分配的缓冲区内存
	cxt->pstore.bufsize = 0;  // 将缓冲区大小设置为 0

	persistent_ram_free(cxt->mprz);  // 释放用于存储 pmsg 日志的持久 RAM 区域
	persistent_ram_free(cxt->cprz);  // 释放用于存储控制台日志的持久 RAM 区域
	ramoops_free_przs(cxt);  // 释放所有其他持久 RAM 区域（例如 dmesg 和 ftrace）

	return 0;  // 返回成功
}

// 定义与设备树兼容性的结构体数组，用于匹配设备树中的设备
static const struct of_device_id dt_match[] = {
	{ .compatible = "ramoops" },	// 指定与"ramoops"兼容的设备
	{}	// 结尾标志，表示数组结束
};

// 定义 platform_driver 结构，用于注册驱动程序
static struct platform_driver ramoops_driver = {
	.probe		= ramoops_probe,	// 指定 probe 函数，用于初始化设备
	.remove		= ramoops_remove,	// 指定 remove 函数，用于清理设备
	.driver		= {
		.name		= "ramoops",	// 驱动程序名称
		.of_match_table	= dt_match,	// 指向设备树匹配表的指针
	},
};

// 定义一个内联函数，用于注销虚拟平台设备
static inline void ramoops_unregister_dummy(void)
{
	platform_device_unregister(dummy);	// 注销 dummy 设备
	dummy = NULL;	// 将 dummy 指针设置为 NULL，避免野指针问题
}

// 定义了一个名为 ramoops_register_dummy 的函数，用于在内核启动时注册一个虚拟的平台设备，以便可以通过模块参数配置 ramoops 模块
static void __init ramoops_register_dummy(void)
{
	struct ramoops_platform_data pdata;

	/*
	 * Prepare a dummy platform data structure to carry the module
	 * parameters. If mem_size isn't set, then there are no module
	 * parameters, and we can skip this.
	 */
	/*
	 * 准备一个虚拟的平台数据结构来携带模块参数。如果没有设置 mem_size，
	 * 则表示没有模块参数，我们可以跳过这一步。
	 */
	if (!mem_size)	// 如果内存大小没有设置
		return;	// 直接返回，不进行任何操作

	pr_info("using module parameters\n");	// 输出日志信息，使用模块参数

	memset(&pdata, 0, sizeof(pdata));  // 初始化 pdata 结构体
	pdata.mem_size = mem_size;  // 设置内存大小
	pdata.mem_address = mem_address;  // 设置物理内存地址
	pdata.mem_type = mem_type;  // 设置内存类型
	pdata.record_size = record_size;  // 设置记录大小
	pdata.console_size = ramoops_console_size;  // 设置控制台大小
	pdata.ftrace_size = ramoops_ftrace_size;  // 设置 ftrace 日志大小
	pdata.pmsg_size = ramoops_pmsg_size;  // 设置 pmsg 日志大小
	/* If "max_reason" is set, its value has priority over "dump_oops". */
	 /*
	 * 如果设置了 "max_reason"，其值有优先权。否则，如果设置了 "dump_oops"，
	 * 根据其值解析为 "max_reason"。如果两者都未显式设置，使用默认值。
	 */
	if (ramoops_max_reason >= 0)	// 如果明确设置了最大原因
		pdata.max_reason = ramoops_max_reason;	// 使用该值
	/* Otherwise, if "dump_oops" is set, parse it into "max_reason". */
	else if (ramoops_dump_oops != -1)	// 如果未设置最大原因但设置了 dump_oops
		pdata.max_reason = ramoops_dump_oops ? KMSG_DUMP_OOPS
						     : KMSG_DUMP_PANIC;	// 根据 dump_oops 的值决定
	/* And if neither are explicitly set, use the default. */
	else	// 如果两者都未设置
		pdata.max_reason = KMSG_DUMP_OOPS;	// 使用默认的崩溃日志类型
	pdata.flags = RAMOOPS_FLAG_FTRACE_PER_CPU;	// 设置 ftrace 标志为每个 CPU 一个记录

	/*
	 * For backwards compatibility ramoops.ecc=1 means 16 bytes ECC
	 * (using 1 byte for ECC isn't much of use anyway).
	 */
	/*
	 * 为了向后兼容，ramoops.ecc=1 意味着 16 字节的 ECC
	 * （使用 1 字节的 ECC 并不实用）。
	 */
	pdata.ecc_info.ecc_size = ramoops_ecc == 1 ? 16 : ramoops_ecc;	// 设置 ECC 大小

	// 注册一个虚拟平台设备，携带 pdata 数据
	dummy = platform_device_register_data(NULL, "ramoops", -1,
			&pdata, sizeof(pdata));
	if (IS_ERR(dummy)) {	// 如果设备注册失败
		pr_info("could not create platform device: %ld\n",
			PTR_ERR(dummy));	// 输出错误信息
		dummy = NULL;	// 将 dummy 设为 NULL 避免野指针问题
	}
}

static int __init ramoops_init(void)
{
	int ret;	// 定义返回值变量

	ramoops_register_dummy();	// 注册一个虚拟的 platform 设备，用于通过模块参数配置 ramoops
	// 注册 platform 驱动程序
	ret = platform_driver_register(&ramoops_driver);
	if (ret != 0)	// 如果驱动程序注册失败
		ramoops_unregister_dummy();	// 注销之前注册的虚拟设备

	return ret;	// 返回注册结果
}
postcore_initcall(ramoops_init);

static void __exit ramoops_exit(void)
{
	platform_driver_unregister(&ramoops_driver);	// 注销 platform 驱动程序
	ramoops_unregister_dummy();	// 注销虚拟的 platform 设备
}
module_exit(ramoops_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marco Stornelli <marco.stornelli@gmail.com>");
MODULE_DESCRIPTION("RAM Oops/Panic logger/driver");

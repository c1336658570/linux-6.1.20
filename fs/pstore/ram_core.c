// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Google, Inc.
 */

// pstore/ram 后端的实现,dram的读写操作

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/memblock.h>
#include <linux/pstore_ram.h>
#include <linux/rslib.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/page.h>

/**
 * struct persistent_ram_buffer - persistent circular RAM buffer
 *
 * @sig:
 *	signature to indicate header (PERSISTENT_RAM_SIG xor PRZ-type value)
 * @start:
 *	offset into @data where the beginning of the stored bytes begin
 * @size:
 *	number of valid bytes stored in @data
 */
/**
 * struct persistent_ram_buffer - 持久的环形RAM缓冲区结构
 *
 * @sig:
 * 用于指示头部的签名（PERSISTENT_RAM_SIG 异或 PRZ 类型值）
 * @start:
 * 存储字节开始处在 @data 中的偏移量
 * @size:
 * 在 @data 中存储的有效字节数
 */
struct persistent_ram_buffer {
	uint32_t    sig;    // 缓冲区头部的签名
	atomic_t    start;  // 开始位置的偏移量，使用原子类型保证操作的原子性
	atomic_t    size;   // 缓冲区中的有效字节数，使用原子类型保证操作的原子性
	uint8_t     data[]; // 柔性数组成员，用于存储实际的数据
};

/* 定义持久性RAM区域的签名常量，这里"DBGC"是一个魔数，用于标识数据结构或内存块。 */
#define PERSISTENT_RAM_SIG (0x43474244) /* DBGC */

/*
 * 获取持久性RAM区域的缓冲区大小。
 * @prz: 指向持久性RAM区域的指针。
 * 返回值: 缓冲区的当前大小。
 */
static inline size_t buffer_size(struct persistent_ram_zone *prz)
{
	return atomic_read(&prz->buffer->size);	// 返回持久性RAM区域的缓冲区大小
}

/*
 * 获取持久性RAM区域的缓冲区起始位置。
 * @prz: 指向持久性RAM区域的指针。
 * 返回值: 缓冲区的起始偏移量。
 */
static inline size_t buffer_start(struct persistent_ram_zone *prz)
{
	return atomic_read(&prz->buffer->start);	// 返回持久性RAM区域的缓冲区起始位置
}

/* increase and wrap the start pointer, returning the old value */
/* 增加并环绕起始指针，返回旧值 */
static size_t buffer_start_add(struct persistent_ram_zone *prz, size_t a)
{
	int old;  // 用于存储旧的起始位置
	int new;  // 计算新的起始位置
	unsigned long flags = 0;  // 用于保存中断状态，因为可能需要禁用中断

	/*
	 * 如果不使用PRZ_FLAG_NO_LOCK标志，则加锁以保护缓冲区的修改。
	 * 这通过自旋锁来保证多核CPU环境下的数据一致性和线程安全。
	 */
	// 检查是否需要锁定缓冲区
	if (!(prz->flags & PRZ_FLAG_NO_LOCK))
		raw_spin_lock_irqsave(&prz->buffer_lock, flags);	// 锁定缓冲区，禁用中断

	old = atomic_read(&prz->buffer->start);	// 读取当前起始位置
	/* 计算新的起始位置。 */
	new = old + a;	// 增加a大小到起始位置
	// 确保起始位置不超出缓冲区总大小，如果新的起始位置超过了缓冲区的大小，则进行环绕。
	while (unlikely(new >= prz->buffer_size))
		new -= prz->buffer_size;	// 环绕处理，如果超过了缓冲区大小则从头开始
	atomic_set(&prz->buffer->start, new);	// 设置新的起始位置。

	// 如果之前加锁了，现在解锁
	if (!(prz->flags & PRZ_FLAG_NO_LOCK))
		raw_spin_unlock_irqrestore(&prz->buffer_lock, flags);	// 解锁缓冲区，恢复中断

	return old;	// 返回更新前的起始位置
}

/* increase the size counter until it hits the max size */
/* 增加大小计数器，直至达到最大大小 */
static void buffer_size_add(struct persistent_ram_zone *prz, size_t a)
{
	size_t old;  // 用于存储旧的大小值
	size_t new;  // 用于存储计算后的新大小值
	unsigned long flags = 0;  // 用于保存中断状态

	// 检查是否需要锁定缓冲区
	if (!(prz->flags & PRZ_FLAG_NO_LOCK))
		raw_spin_lock_irqsave(&prz->buffer_lock, flags);  // 如果需要锁定，则加锁并保存中断状态

	old = atomic_read(&prz->buffer->size);  // 从原子变量读取当前缓冲区大小
	if (old == prz->buffer_size)  // 如果当前大小已经是缓冲区的最大值
		goto exit;  // 直接跳到解锁处理

	new = old + a;  // 计算增加后的新大小
	if (new > prz->buffer_size)  // 如果新大小超过了缓冲区的物理限制
		new = prz->buffer_size;  // 设置新大小为缓冲区的最大大小
	atomic_set(&prz->buffer->size, new);  // 设置缓冲区的新大小

exit:
	// 如果之前加锁了，现在解锁
	if (!(prz->flags & PRZ_FLAG_NO_LOCK))
		raw_spin_unlock_irqrestore(&prz->buffer_lock, flags);  // 解锁缓冲区并恢复之前的中断状态
}

// 对数据进行Reed-Solomon编码以增加容错能力
// 定义函数，使用notrace属性来避免跟踪此函数以减少干扰和性能损耗
static void notrace persistent_ram_encode_rs8(struct persistent_ram_zone *prz,
	uint8_t *data, size_t len, uint8_t *ecc)
{
	int i;  // 用于循环的变量

	/* Initialize the parity buffer */
	/* 初始化奇偶校验缓冲区 */
	// 使用memset将奇偶校验数组初始化为0，准备用于存储新的奇偶校验数据
	memset(prz->ecc_info.par, 0,
	       prz->ecc_info.ecc_size * sizeof(prz->ecc_info.par[0]));

	// 调用encode_rs8函数进行Reed-Solomon编码，输入是data数组，输出是填充在ecc_info.par中的奇偶校验数据
	encode_rs8(prz->rs_decoder, data, len, prz->ecc_info.par, 0);

	// 遍历每个生成的奇偶校验字节
	for (i = 0; i < prz->ecc_info.ecc_size; i++)
		ecc[i] = prz->ecc_info.par[i];  // 将计算出的奇偶校验字节复制到ecc数组，用于传输或存储
}

// 用于解码使用Reed-Solomon算法编码的数据，以便从可能发生的错误中恢复数据
// 定义函数，用于解码使用Reed-Solomon算法编码的数据
static int persistent_ram_decode_rs8(struct persistent_ram_zone *prz,
	void *data, size_t len, uint8_t *ecc)
{
	int i;	// 用于循环的变量

	// 遍历每个奇偶校验字节
	for (i = 0; i < prz->ecc_info.ecc_size; i++)
		prz->ecc_info.par[i] = ecc[i];	// 将传入的奇偶校验数据复制到persistent_ram_zone的奇偶校验缓冲区
	// 调用decode_rs8函数进行Reed-Solomon解码，输入是data数组和奇偶校验数据
	// 返回值是解码操作的结果，通常表示修复的错误数，如果无法修复则可能返回负值错误代码
	return decode_rs8(prz->rs_decoder, data, prz->ecc_info.par, len,
				NULL, 0, NULL, 0, NULL);
}

// 用于更新持久性RAM区域中指定数据块的Reed-Solomon纠错编码
// 定义不进行跟踪的函数，用于更新持久性RAM区域的纠错编码
static void notrace persistent_ram_update_ecc(struct persistent_ram_zone *prz,
	unsigned int start, unsigned int count)
{
	struct persistent_ram_buffer *buffer = prz->buffer;	// 获取持久性RAM区域的缓冲区指针
	uint8_t *buffer_end = buffer->data + prz->buffer_size;	// 计算缓冲区数据末尾的地址
	uint8_t *block;	// 用于指向当前处理的数据块
	uint8_t *par;		// 用于指向当前数据块的纠错编码部分
	int ecc_block_size = prz->ecc_info.block_size;	// 获取每个数据块的大小（用于纠错编码）
	int ecc_size = prz->ecc_info.ecc_size;	// 获取纠错编码的大小
	int size = ecc_block_size;	// 初始化处理的数据块大小为纠错块大小

	if (!ecc_size)
		return;	// 如果纠错编码大小为0，无需处理，直接返回

	// 计算第一个需要处理的数据块的起始地址（对齐到纠错块大小）
	block = buffer->data + (start & ~(ecc_block_size - 1));
	// 计算对应的纠错编码的起始地址
	par = prz->par_buffer + (start / ecc_block_size) * ecc_size;

	do {
		if (block + ecc_block_size > buffer_end)
			size = buffer_end - block;	// 如果数据块超出缓冲区末尾，调整处理的大小
		persistent_ram_encode_rs8(prz, block, size, par);	// 对数据块进行纠错编码
		block += ecc_block_size;	// 移动到下一个数据块
		par += ecc_size;	// 移动到下一个纠错编码块
	} while (block < buffer->data + start + count);	// 循环处理指定区域内的所有数据块
}

// 义了一个函数，用于更新持久性RAM区域中缓冲区头部的Reed-Solomon纠错编码
// // 定义一个函数，用于更新持久性RAM区域中的缓冲区头部的纠错编码
static void persistent_ram_update_header_ecc(struct persistent_ram_zone *prz)
{
	struct persistent_ram_buffer *buffer = prz->buffer;	// 获取持久性RAM区域的缓冲区指针

	if (!prz->ecc_info.ecc_size)
		return;	// 如果纠错编码大小为0，无需处理，直接返回

	// 对缓冲区头部进行纠错编码，使用Reed-Solomon算法进行编码，
	// 编码结果存储在prz->par_header中
	persistent_ram_encode_rs8(prz, (uint8_t *)buffer, sizeof(*buffer),
				  prz->par_header);
}

// 定义了一个函数，用于对持久性RAM区域中已存储的数据块执行Reed-Solomon纠错编码检查和修正
// 定义一个函数，用于检查和修正持久性RAM区域中的数据块的纠错编码
static void persistent_ram_ecc_old(struct persistent_ram_zone *prz)
{
	struct persistent_ram_buffer *buffer = prz->buffer;  // 获取持久性RAM区域的缓冲区指针
	uint8_t *block;  // 指向当前处理的数据块
	uint8_t *par;    // 指向当前数据块的纠错编码部分

	if (!prz->ecc_info.ecc_size)
		return;  // 如果纠错编码大小为0，无需处理，直接返回

	block = buffer->data;  // 设置block指向缓冲区的开始
	par = prz->par_buffer;  // 设置par指向纠错编码的开始
	while (block < buffer->data + buffer_size(prz)) {  // 循环遍历所有数据块
		int numerr;  // 用于存储纠错过程中发现的错误数
		int size = prz->ecc_info.block_size;  // 设置处理的数据块大小为纠错块大小
		if (block + size > buffer->data + prz->buffer_size)  // 如果数据块末尾超出缓冲区
			size = buffer->data + prz->buffer_size - block;  // 调整最后一个数据块的大小
		numerr = persistent_ram_decode_rs8(prz, block, size, par);  // 对数据块进行纠错解码
		if (numerr > 0) {
			pr_devel("error in block %p, %d\n", block, numerr);  // 如果有错误被修正，记录修正的错误数
			prz->corrected_bytes += numerr;  // 累计修正的总字节数
		} else if (numerr < 0) {
			pr_devel("uncorrectable error in block %p\n", block);  // 如果错误无法修正，记录错误信息
			prz->bad_blocks++;  // 增加无法修正的块的计数
		}
		block += prz->ecc_info.block_size;  // 移动到下一个数据块
		par += prz->ecc_info.ecc_size;  // 移动到下一个纠错编码块
	}
}

// 定义了一个函数，用于初始化持久性RAM区域的纠错编码设置
static int persistent_ram_init_ecc(struct persistent_ram_zone *prz,
				   struct persistent_ram_ecc_info *ecc_info)
{
	int numerr;	// 用于存储纠错过程中发现的错误数
	struct persistent_ram_buffer *buffer = prz->buffer;	// 获取持久性RAM区域的缓冲区指针
	int ecc_blocks;	// 用于计算需要多少块纠错编码块
	size_t ecc_total;	// 用于计算纠错编码总大小

	if (!ecc_info || !ecc_info->ecc_size)
		return 0;	// 如果ecc_info为空或ecc_size为0，则直接返回

	// 设置纠错块的大小和参数，如果未指定则使用默认值
	/*
	 * block_size: 这是每个数据块的大小。在纠错编码中，数据被分成多个块，每个块独立进行错误检测和修正。
	 * ecc_size: 这是每个数据块所需的错误更正码的额外字节数。更多的ECC字节意味着能够检测和修正更多的错误。
	 * symsize: 符号大小，通常用位（bit）表示。这决定了纠错算法处理的数据单位。例如，8位symsize意味着算法将数据以每8位进行一次处理。
	 * poly: 这是一个生成多项式，用于Reed-Solomon编码。这个多项式决定了生成纠错码的方法。
	 */
	prz->ecc_info.block_size = ecc_info->block_size ?: 128;
	prz->ecc_info.ecc_size = ecc_info->ecc_size ?: 16;
	prz->ecc_info.symsize = ecc_info->symsize ?: 8;
	prz->ecc_info.poly = ecc_info->poly ?: 0x11d;

	// 计算需要多少块纠错编码块，考虑每块纠错编码的大小
	/*
	 * 计算ECC块数 (ecc_blocks):
	 * 使用DIV_ROUND_UP(prz->buffer_size - prz->ecc_info.ecc_size, prz->ecc_info.block_size + prz->ecc_info.ecc_size)来计算。
	 * DIV_ROUND_UP是一个宏，用于实现向上取整除法。
	 * 这里的计算逻辑是：从总的缓冲区大小prz->buffer_size中减去一个ECC块的大小（因为至少需要一个ECC块空间），
	 * 然后除以每个ECC块加上其对应的数据块的总大小（prz->ecc_info.block_size + prz->ecc_info.ecc_size）。
	 * 这样计算的结果是，需要多少个数据+ECC块组合才能覆盖剩余的缓冲区。
	 */
	ecc_blocks = DIV_ROUND_UP(prz->buffer_size - prz->ecc_info.ecc_size,
				  prz->ecc_info.block_size +
				  prz->ecc_info.ecc_size);
	/*
	 * 使用(ecc_blocks + 1) * prz->ecc_info.ecc_size来计算。这个计算是基于ecc_blocks的结果，
	 * 但考虑到可能存在不完全填满的最后一个块，因此在块数上加1，确保有足够的ECC空间。
	 */
	ecc_total = (ecc_blocks + 1) * prz->ecc_info.ecc_size;
	if (ecc_total >= prz->buffer_size) {
		// 如果纠错编码总大小超过了缓冲区大小，打印错误信息并返回错误
		pr_err("%s: invalid ecc_size %u (total %zu, buffer size %zu)\n",
		       __func__, prz->ecc_info.ecc_size,
		       ecc_total, prz->buffer_size);
		return -EINVAL;
	}

	// 更新缓冲区的可用大小，分配空间给纠错编码部分
	prz->buffer_size -= ecc_total;
	prz->par_buffer = buffer->data + prz->buffer_size;
	prz->par_header = prz->par_buffer +
			  ecc_blocks * prz->ecc_info.ecc_size;

	/*
	 * first consecutive root is 0
	 * primitive element to generate roots = 1
	 */
	/*
	 * 初始化Reed-Solomon纠错编码器，指定符号大小，多项式，根的起始位置和间隔
	 */
	prz->rs_decoder = init_rs(prz->ecc_info.symsize, prz->ecc_info.poly,
				  0, 1, prz->ecc_info.ecc_size);
	if (prz->rs_decoder == NULL) {
		pr_info("init_rs failed\n");	// 如果初始化失败，打印信息并返回错误
		return -EINVAL;
	}

	/* allocate workspace instead of using stack VLA */
	// 分配空间给纠错编码的工作空间，使用动态内存分配而非栈
	prz->ecc_info.par = kmalloc_array(prz->ecc_info.ecc_size,
					  sizeof(*prz->ecc_info.par),
					  GFP_KERNEL);
	if (!prz->ecc_info.par) {
		// 如果内存分配失败，打印错误信息并返回内存不足错误
		pr_err("cannot allocate ECC parity workspace\n");
		return -ENOMEM;
	}

	prz->corrected_bytes = 0;
	prz->bad_blocks = 0;

	// 对缓冲区头部进行纠错解码，并记录任何发现的错误
	numerr = persistent_ram_decode_rs8(prz, buffer, sizeof(*buffer),
					   prz->par_header);
	if (numerr > 0) {
		// 如果发现并修正了错误，记录信息和修正的字节数
		pr_info("error in header, %d\n", numerr);
		prz->corrected_bytes += numerr;
	} else if (numerr < 0) {
		// 如果发现无法修正的错误，记录信息并增加坏块计数
		pr_info_ratelimited("uncorrectable error in header\n");
		prz->bad_blocks++;
	}

	return 0;	// 成功完成初始化
}

// 定义了一个函数，用于生成描述持久性RAM区域的纠错编码(ECC)状态的字符串
// 定义一个函数，返回一个字符串描述ECC的状态
ssize_t persistent_ram_ecc_string(struct persistent_ram_zone *prz,
	char *str, size_t len)
{
	ssize_t ret;	// 用于存储snprintf函数的返回值，表示写入字符串的字节数

	if (!prz->ecc_info.ecc_size)
		return 0;	// 如果ECC大小为0，表示没有ECC，直接返回0

	// 如果存在已修正的错误字节或者无法修正的块
	if (prz->corrected_bytes || prz->bad_blocks)
		// 使用snprintf将ECC的状态格式化为字符串，包括已修正的字节数和无法恢复的块数
		ret = snprintf(str, len, ""
			"\nECC: %d Corrected bytes, %d unrecoverable blocks\n",
			prz->corrected_bytes, prz->bad_blocks);
	else
		// 如果没有检测到错误，使用snprintf输出“没有检测到错误”的信息
		ret = snprintf(str, len, "\nECC: No errors detected\n");

	return ret;	// 返回生成的字符串长度
}

// 定义了一个函数，用于更新持久性RAM区域中的数据，并相应地更新其纠错编码(ECC)
static void notrace persistent_ram_update(struct persistent_ram_zone *prz,
	const void *s, unsigned int start, unsigned int count)
{
	struct persistent_ram_buffer *buffer = prz->buffer;	// 获取持久性RAM区域的缓冲区指针
	// 将数据从源指针s复制到持久性RAM区域的指定位置（buffer->data + start）
	// 复制的字节数为count，这是一个直接内存访问操作
	memcpy_toio(buffer->data + start, s, count);
	// 调用persistent_ram_update_ecc函数更新对应数据区域的纠错编码
	// 这是为了保证数据的完整性和可恢复性
	persistent_ram_update_ecc(prz, start, count);
}

// 定义一个函数，用于将用户空间的数据更新到持久化 RAM 区域
static int notrace persistent_ram_update_user(struct persistent_ram_zone *prz,
	const void __user *s, unsigned int start, unsigned int count)
{
	struct persistent_ram_buffer *buffer = prz->buffer;	// 获取持久化 RAM 缓冲区
	int ret = unlikely(copy_from_user(buffer->data + start, s, count)) ?
		-EFAULT : 0;	// 将用户空间的数据复制到缓冲区中，如果失败返回 -EFAULT 错误码
	persistent_ram_update_ecc(prz, start, count);	// 更新该区域的 ECC（错误校正码），保证数据完整性
	return ret;	// 返回结果，0 表示成功，-EFAULT 表示有错误发生
}

/*
 * 此函数的关键作用是在系统可能重启之前保存当前RAM中的数据。通过复制当前缓冲区内容到新分配的内存空间，
 * 它确保重启后的数据恢复。该函数首先检查是否需要执行ECC纠错，然后按照数据的存储布局（循环缓冲区），
 * 正确地复制数据到新分配的内存。这样，即使原始缓冲区在重启后被重用或修改，保存的数据也能保持不变。
 */
// 定义了一个函数，用于保存持久性RAM区域中的当前数据，通常是在系统重启前。这有助于确保在发生系统崩溃或关键事件后，重要数据不会丢失。
// 定义一个函数，用于保存持久性RAM区域中的当前数据
void persistent_ram_save_old(struct persistent_ram_zone *prz)
{
	struct persistent_ram_buffer *buffer = prz->buffer;	// 获取持久性RAM区域的缓冲区指针
	size_t size = buffer_size(prz);	// 获取当前缓冲区的数据大小
	size_t start = buffer_start(prz);	// 获取当前数据的起始位置

	if (!size)
		return;	// 如果没有数据大小，则直接返回，无需保存

	if (!prz->old_log) {
		persistent_ram_ecc_old(prz);	// 在分配新的日志空间之前，先检查并纠正现有数据的任何ECC错误
		prz->old_log = kmalloc(size, GFP_KERNEL);	// 为旧数据分配新的内存空间
	}
	if (!prz->old_log) {
		 // 如果内存分配失败，打印错误信息并返回
		pr_err("failed to allocate buffer\n");
		return;
	}

	prz->old_log_size = size;	// 设置旧日志的大小
	// 从当前数据的起始位置开始复制数据到旧日志中，直到缓冲区末尾
	memcpy_fromio(prz->old_log, &buffer->data[start], size - start);
	// 如果数据是循环存储的，复制开始部分的数据，填充旧日志的剩余部分
	memcpy_fromio(prz->old_log + size - start, &buffer->data[0], start);
}

// 定义了一个函数persistent_ram_write，用于向持久性RAM区域写入数据
// 定义一个不进行跟踪的函数，用于向持久性RAM区域写入数据
int notrace persistent_ram_write(struct persistent_ram_zone *prz,
	const void *s, unsigned int count)
{
	
	int rem;	// 用于存储剩余未写部分的大小
	int c = count;	// 将要写入的数据总大小
	size_t start;	// 计算数据应该开始写入的位置

	// 如果尝试写入的数据大小超过了缓冲区总大小
	if (unlikely(c > prz->buffer_size)) {
		s += c - prz->buffer_size;	// 调整源数据指针，仅写入最后的prz->buffer_size部分
		c = prz->buffer_size;	// 调整写入大小为缓冲区大小
	}

	buffer_size_add(prz, c);	// 更新持久性RAM区域中已用缓冲区大小

	start = buffer_start_add(prz, c);	// 更新缓冲区的开始位置，获取旧的开始位置

	rem = prz->buffer_size - start;	 // 计算从开始位置到缓冲区末尾的剩余空间大小
	if (unlikely(rem < c)) {	// 如果剩余空间不足以存放所有数据
		persistent_ram_update(prz, s, start, rem);	// 先写入剩余空间部分
		s += rem;	// 移动源数据指针
		c -= rem;	// 减少剩余要写入的数据大小
		start = 0;	// 新的写入开始位置设置为缓冲区开始
	}
	persistent_ram_update(prz, s, start, c);	// 写入剩余或全部数据

	persistent_ram_update_header_ecc(prz);	// 更新持久性RAM区域头部的ECC

	return count;	// 返回成功写入的数据大小
}

// 定义了一个函数，用于从用户空间向持久性RAM区域写入数据。
// 定义一个不进行跟踪的函数，用于从用户空间向持久性RAM区域写入数据
int notrace persistent_ram_write_user(struct persistent_ram_zone *prz,
	const void __user *s, unsigned int count)
{
	int rem, ret = 0, c = count;	// rem用于存储剩余未写部分的大小，ret用于存储返回状态，c是要写入的数据总大小
	size_t start;	// 用于存储数据应该开始写入的位置

	// 如果尝试写入的数据大小超过了缓冲区总大小
	if (unlikely(c > prz->buffer_size)) {
		s += c - prz->buffer_size;	// 调整源数据指针，仅写入最后的prz->buffer_size部分
		c = prz->buffer_size;	// 调整写入大小为缓冲区大小
	}

	buffer_size_add(prz, c);	// 更新持久性RAM区域中已用缓冲区大小

	start = buffer_start_add(prz, c);	// 更新缓冲区的开始位置，获取旧的开始位置

	rem = prz->buffer_size - start;	// 计算从开始位置到缓冲区末尾的剩余空间大小
	// 如果剩余空间不足以存放所有数据
	if (unlikely(rem < c)) {
		ret = persistent_ram_update_user(prz, s, start, rem);	// 先写入剩余空间部分
		s += rem;	// 移动源数据指针
		c -= rem;	// 减少剩余要写入的数据大小
		start = 0;	// 新的写入开始位置设置为缓冲区开始
	}
	if (likely(!ret))
		ret = persistent_ram_update_user(prz, s, start, c);	// 写入剩余或全部数据

	persistent_ram_update_header_ecc(prz);	// 更新持久性RAM区域头部的ECC

	return unlikely(ret) ? ret : count;	// 如果有错误发生返回错误码，否则返回写入的数据大小
}

size_t persistent_ram_old_size(struct persistent_ram_zone *prz)
{
	return prz->old_log_size;	// 返回持久性RAM区域中旧日志的大小
}

void *persistent_ram_old(struct persistent_ram_zone *prz)
{
	return prz->old_log;	// 返回指向持久性RAM区域中旧日志的指针
}

void persistent_ram_free_old(struct persistent_ram_zone *prz)
{
	kfree(prz->old_log);  // 释放持久性RAM区域中旧日志所占用的内存
	prz->old_log = NULL;  // 将旧日志的指针设为NULL，避免野指针
	prz->old_log_size = 0;  // 将旧日志的大小重置为0
}

void persistent_ram_zap(struct persistent_ram_zone *prz)
{
	atomic_set(&prz->buffer->start, 0);  // 将持久性RAM区域的开始位置重置为0
	atomic_set(&prz->buffer->size, 0);  // 将持久性RAM区域的大小重置为0
	persistent_ram_update_header_ecc(prz);  // 更新持久性RAM区域头部的纠错编码（ECC）
}

#define MEM_TYPE_WCOMBINE	0  // 写组合内存类型
#define MEM_TYPE_NONCACHED	1  // 非缓存内存类型
#define MEM_TYPE_NORMAL		2  // 普通缓存内存类型

// 定义了一个函数，用于根据物理地址和内存类型将一段物理内存映射到虚拟地址空间
// 定义一个函数，用于将一段物理内存映射到虚拟地址空间
static void *persistent_ram_vmap(phys_addr_t start, size_t size,
		unsigned int memtype)
{
	struct page **pages;  // 页面指针数组，用于vmap
	phys_addr_t page_start;  // 页面对齐的起始物理地址
	unsigned int page_count;  // 需要映射的页面数量
	pgprot_t prot;  // 页面保护属性
	unsigned int i;  // 循环变量
	void *vaddr;  // 最终映射得到的虚拟地址

	page_start = start - offset_in_page(start);  // 对齐起始地址到页面边界
	page_count = DIV_ROUND_UP(size + offset_in_page(start), PAGE_SIZE);  // 计算包括偏移在内的总页面数

	switch (memtype) {	// 根据内存类型设置页面保护属性
	case MEM_TYPE_NORMAL:
		prot = PAGE_KERNEL;	// 普通内存使用正常页面属性
		break;
	case MEM_TYPE_NONCACHED:
		prot = pgprot_noncached(PAGE_KERNEL);	// 非缓存内存使用非缓存页面属性
		break;
	case MEM_TYPE_WCOMBINE:
		prot = pgprot_writecombine(PAGE_KERNEL);	// 写组合内存使用写组合页面属性
		break;
	default:
		pr_err("invalid mem_type=%d\n", memtype);	// 如果内存类型无效，则打印错误并返回NULL
		return NULL;
	}

	pages = kmalloc_array(page_count, sizeof(struct page *), GFP_KERNEL);	// 为页面数组分配内存
	if (!pages) {
		pr_err("%s: Failed to allocate array for %u pages\n",
		       __func__, page_count);	// 如果分配失败，打印错误并返回NULL
		return NULL;
	}

	for (i = 0; i < page_count; i++) {	// 遍历所有页面
		phys_addr_t addr = page_start + i * PAGE_SIZE;	// 计算每一页的物理地址
		pages[i] = pfn_to_page(addr >> PAGE_SHIFT);	// 将物理页号转换为页面结构体指针
	}
	/*
	 * VM_IOREMAP used here to bypass this region during vread()
	 * and kmap_atomic() (i.e. kcore) to avoid __va() failures.
	 */
	/*
	 * 在这里使用VM_IOREMAP标志来在vread()和kmap_atomic()中绕过此区域，
	 * 避免__va()函数调用失败。
	 */
	vaddr = vmap(pages, page_count, VM_MAP | VM_IOREMAP, prot);	// 使用vmap映射页面数组到虚拟地址
	kfree(pages);	// 释放页面数组内存

	/*
	 * Since vmap() uses page granularity, we must add the offset
	 * into the page here, to get the byte granularity address
	 * into the mapping to represent the actual "start" location.
	 */
	/*
	 * 由于vmap()使用页面粒度，我们必须在这里添加到页面的偏移，
	 * 以获得映射中的字节粒度地址，以代表实际的“起始”位置。
	 */
	return vaddr + offset_in_page(start);	// 返回实际的虚拟地址起始位置
}

// 定义了一个函数，用于将一段物理内存映射到虚拟地址空间，并确保该内存区域已经成功被系统请求使用。
// 定义一个函数，用于将物理内存映射到虚拟地址空间
/*
 * 这个函数主要用于在设备驱动中将指定的物理内存区域映射到虚拟地址空间。
 * 使用request_mem_region函数来确保请求的内存区域未被其他驱动或系统部分占用，
 * 从而确保内存映射的安全性和唯一性。根据memtype参数的不同，可以选择不同类型
 * 的内存映射方法：普通映射或写组合映射。
 */
static void *persistent_ram_iomap(phys_addr_t start, size_t size,
		unsigned int memtype, char *label)
{
	void *va;

	// 请求对指定物理地址范围的内存区域的独占访问权限
	// 如果请求失败，打印错误信息并返回NULL
	if (!request_mem_region(start, size, label ?: "ramoops")) {
		pr_err("request mem region (%s 0x%llx@0x%llx) failed\n",
			label ?: "ramoops",
			(unsigned long long)size, (unsigned long long)start);
		return NULL;
	}

	if (memtype)
		va = ioremap(start, size);	// 如果memtype为真，使用普通的内存映射
	else
		va = ioremap_wc(start, size);	// 否则，使用写组合的内存映射

	/*
	 * Since request_mem_region() and ioremap() are byte-granularity
	 * there is no need handle anything special like we do when the
	 * vmap() case in persistent_ram_vmap() above.
	 */
	/*
	 * 由于request_mem_region()和ioremap()是以字节粒度处理的，
	 * 没有必要像persistent_ram_vmap()中的vmap()情况那样处理特殊情况。
	 */
	return va;	// 返回映射的虚拟地址
}

// 义了一个函数，用于初始化一个持久性RAM区域（persistent_ram_zone）并映射其物理地址到虚拟地址。
// 定义一个函数，用于映射持久性RAM区域的物理内存到虚拟内存
static int persistent_ram_buffer_map(phys_addr_t start, phys_addr_t size,
		struct persistent_ram_zone *prz, int memtype)
{
	prz->paddr = start;  // 设置持久性RAM区域的物理地址
	prz->size = size;  // 设置持久性RAM区域的大小

	// 检查给定的物理页号是否有效
	if (pfn_valid(start >> PAGE_SHIFT))
		// 如果有效，则使用vmap进行映射
		prz->vaddr = persistent_ram_vmap(start, size, memtype);
	else
		// 如果不有效，使用iomap进行映射
		prz->vaddr = persistent_ram_iomap(start, size, memtype,
						  prz->label);

	// 检查映射是否成功
	if (!prz->vaddr) {
		// 如果映射失败，打印错误信息
		pr_err("%s: Failed to map 0x%llx pages at 0x%llx\n", __func__,
			(unsigned long long)size, (unsigned long long)start);
		return -ENOMEM;	// 返回内存错误
	}

	prz->buffer = prz->vaddr;	// 将映射的虚拟地址设置为缓冲区的起始地址
	// 计算除去结构体自身大小后的可用缓冲区大小
	prz->buffer_size = size - sizeof(struct persistent_ram_buffer);

	return 0;	// 返回成功
}

// 定义了一个函数，用于在初始化持久性RAM区域后进行进一步的配置和检查。
// 定义一个函数，用于初始化后配置持久性RAM区域
/*
 * 此函数是持久性RAM管理逻辑的一部分，它主要负责在持久性RAM区域初始化后，检查并处理现有数据的有效性和完整性。
 * 函数首先尝试初始化ECC，然后验证区域的签名。根据签名和数据状态，它可能保存旧数据、清除数据或重置数据区域的签名。
 * 这个过程确保了持久性RAM区域在系统重启后可以安全可靠地使用。
 */
static int persistent_ram_post_init(struct persistent_ram_zone *prz, u32 sig,
				    struct persistent_ram_ecc_info *ecc_info)
{
	int ret;  // 用于存储函数调用的返回值
	bool zap = !!(prz->flags & PRZ_FLAG_ZAP_OLD);  // 根据标志判断是否需要在发现旧数据时清除它们

	ret = persistent_ram_init_ecc(prz, ecc_info);  // 初始化纠错编码设置
	if (ret) {
		pr_warn("ECC failed %s\n", prz->label);  // 如果ECC初始化失败，打印警告信息
		return ret;  // 返回错误代码
	}

	sig ^= PERSISTENT_RAM_SIG;  // 通过异或操作生成一个签名，用于验证数据完整性

	if (prz->buffer->sig == sig) {	// 检查持久性RAM区域的签名是否匹配
		if (buffer_size(prz) == 0) {	// 检查缓冲区是否为空
			pr_debug("found existing empty buffer\n");	// 如果为空，打印调试信息
			return 0;	// 返回成功
		}

		if (buffer_size(prz) > prz->buffer_size ||
		    buffer_start(prz) > buffer_size(prz)) {	// 检查缓冲区大小和起始位置是否有效
			pr_info("found existing invalid buffer, size %zu, start %zu\n",
				buffer_size(prz), buffer_start(prz));	// 如果无效，打印信息并设置清除标志
			zap = true;
		} else {
			pr_debug("found existing buffer, size %zu, start %zu\n",
				 buffer_size(prz), buffer_start(prz));	// 如果有效，打印调试信息
			persistent_ram_save_old(prz);	// 保存旧的缓冲区数据
		}
	} else {
		pr_debug("no valid data in buffer (sig = 0x%08x)\n",
			 prz->buffer->sig);	// 如果签名不匹配，打印调试信息
		prz->buffer->sig = sig;	// 设置新的签名
		zap = true;	// 设置清除标志
	}

	/* Reset missing, invalid, or single-use memory area. */
	/* 重置缺失的、无效的或一次性使用的内存区域。 */
	if (zap)
		persistent_ram_zap(prz);	// 如果需要，清除持久性RAM区域

	return 0;	// 返回成功
}

// 定义了一个函数，用于清理持久性RAM区域（persistent_ram_zone）相关的资源。
// 定义一个函数，用于释放持久性RAM区域相关的资源
/*
 * 负责在系统不再需要持久性RAM区域时，正确释放所有相关资源，包括解映射虚拟地址、释放物理内存区域、
 * 释放Reed-Solomon解码器以及相关内存空间。这样做是为了防止内存泄漏，确保系统资源得到妥善管理。
 * 通过对不同类型的内存映射（vmap和ioremap）进行适当的处理，确保了资源的正确释放。
 * 此外，还清理了可能存储的旧日志数据和其他动态分配的内存，保持系统的整洁和稳定。
 */
void persistent_ram_free(struct persistent_ram_zone *prz)
{
	if (!prz)
		return;	// 如果传入的持久性RAM区域指针为空，则直接返回

	// 如果有有效的虚拟地址映射
	if (prz->vaddr) {
		// 如果物理地址对应的页框号有效，意味着使用了vmap进行映射
		if (pfn_valid(prz->paddr >> PAGE_SHIFT)) {
			/* We must vunmap() at page-granularity. */
			/* 我们必须以页面粒度进行虚拟地址解映射 */
			vunmap(prz->vaddr - offset_in_page(prz->paddr));
		} else {
			// 如果物理地址对应的页框号无效，意味着使用了ioremap进行映射
			iounmap(prz->vaddr);	// 解映射虚拟地址
			release_mem_region(prz->paddr, prz->size);	// 释放请求的物理内存区域
		}
		prz->vaddr = NULL;	// 清除虚拟地址指针
	}
	if (prz->rs_decoder) {	// 如果存在Reed-Solomon解码器
		free_rs(prz->rs_decoder);	// 释放Reed-Solomon解码器
		prz->rs_decoder = NULL;	// 清除解码器指针
	}
	kfree(prz->ecc_info.par);	// 释放用于存储ECC奇偶校验数据的内存
	prz->ecc_info.par = NULL;	// 清除ECC奇偶校验数据指针

	persistent_ram_free_old(prz);	// 调用函数释放旧的日志数据
	kfree(prz->label);	// 释放存储标签的内存
	kfree(prz);	// 释放持久性RAM区域结构体本身
}

// 定义了一个函数，用于创建和初始化一个新的持久性RAM区域（persistent_ram_zone），包括映射物理内存、初始化ECC和其他设置。
/*
 * 此函数是用来创建并准备一个持久性RAM区域的，它负责分配内存、映射物理地址到虚拟地址、
 * 初始化缓冲区状态、设置纠错编码等。通过使用内核的内存管理功能，确保了持久性RAM区域
 * 可以安全地被访问和使用。如果在任何初始化步骤中发生错误，函数会清理已分配的资源并返回一个错误码。
 */
struct persistent_ram_zone *persistent_ram_new(phys_addr_t start, size_t size,
			u32 sig, struct persistent_ram_ecc_info *ecc_info,
			unsigned int memtype, u32 flags, char *label)
{
	struct persistent_ram_zone *prz;	// 定义一个函数，用于创建一个新的持久性RAM区域
	int ret = -ENOMEM;	// 初始化返回值为内存不足错误

	prz = kzalloc(sizeof(struct persistent_ram_zone), GFP_KERNEL);
	if (!prz) {
		pr_err("failed to allocate persistent ram zone\n");	// 如果内存分配失败，打印错误信息
		goto err;	// 跳转到错误处理代码
	}

	/* Initialize general buffer state. */
	// 初始化通用缓冲区状态
	raw_spin_lock_init(&prz->buffer_lock);  // 初始化自旋锁
	prz->flags = flags;  // 设置区域标志
	prz->label = kstrdup(label, GFP_KERNEL);  // 复制标签字符串


	ret = persistent_ram_buffer_map(start, size, prz, memtype);
	if (ret)
		goto err;	// 如果映射内存失败，跳转到错误处理代码

	ret = persistent_ram_post_init(prz, sig, ecc_info);
	if (ret)
		goto err;	// 如果后续初始化失败，跳转到错误处理代码

	// 打印调试信息，显示区域的各种属性
	pr_debug("attached %s 0x%zx@0x%llx: %zu header, %zu data, %zu ecc (%d/%d)\n",
		prz->label, prz->size, (unsigned long long)prz->paddr,
		sizeof(*prz->buffer), prz->buffer_size,
		prz->size - sizeof(*prz->buffer) - prz->buffer_size,
		prz->ecc_info.ecc_size, prz->ecc_info.block_size);

	return prz;	// 返回新创建的持久性RAM区域
err:
	persistent_ram_free(prz);	// 在发生错误时，清理已分配的资源
	return ERR_PTR(ret);		// 返回错误指针
}

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PSTORE_INTERNAL_H__
#define __PSTORE_INTERNAL_H__

#include <linux/types.h>
#include <linux/time.h>
#include <linux/pstore.h>

/*
 * 声明了一个外部变量kmsg_bytes，类型为unsigned long，用于存储内核消息的字节大小。
 * 这意味着此变量在其他地方（可能是一个C文件中）定义和初始化。
 */
extern unsigned long kmsg_bytes;

/*
 * 如果定义了CONFIG_PSTORE_FTRACE（一个编译时选项），则包含以下代码。
 * 这通常是在内核配置时选择是否启用pstore的ftrace记录功能。
 */
#ifdef CONFIG_PSTORE_FTRACE
/*
 * 声明了两个函数pstore_register_ftrace和pstore_unregister_ftrace，
 * 分别用于注册和注销ftrace到pstore的接口。
 */
extern void pstore_register_ftrace(void);
extern void pstore_unregister_ftrace(void);
/*
 * 声明了一个函数pstore_ftrace_combine_log，用于将源日志(src_log)合并到目标日志(dest_log)中。
 * dest_log是指向目标日志指针的指针，dest_log_size是目标日志大小的指针，
 * src_log是源日志的指针，src_log_size是源日志的大小。
 * 返回类型为ssize_t，通常用于表示执行结果或传输的字节数。
 */

ssize_t pstore_ftrace_combine_log(char **dest_log, size_t *dest_log_size,
				  const char *src_log, size_t src_log_size);
#else
/*
 * 如果CONFIG_PSTORE_FTRACE没有定义，以下是替代的内联定义。
 */
static inline void pstore_register_ftrace(void) {}
static inline void pstore_unregister_ftrace(void) {}
static inline ssize_t
pstore_ftrace_combine_log(char **dest_log, size_t *dest_log_size,
			  const char *src_log, size_t src_log_size)
{
	*dest_log_size = 0;
	return 0;
}
#endif

/*
 * 如果定义了CONFIG_PSTORE_PMSG宏（一个编译时选项），则包括以下内容。
 * 这通常是在内核配置时选择是否启用pstore的平台消息(pmsg)记录功能。
 */
#ifdef CONFIG_PSTORE_PMSG
/*
 * 声明了两个函数pstore_register_pmsg和pstore_unregister_pmsg，
 * 分别用于注册和注销平台消息记录到pstore的接口。
 */
extern void pstore_register_pmsg(void);
extern void pstore_unregister_pmsg(void);
#else
/*
 * 如果CONFIG_PSTORE_PMSG没有定义，以下是替代的内联定义。
 */
static inline void pstore_register_pmsg(void) {}
static inline void pstore_unregister_pmsg(void) {}
#endif

/*
 * 声明一个外部变量psinfo，它是指向pstore_info结构的指针。
 * pstore_info结构包含了与pstore后端相关的信息。
 */
extern struct pstore_info *psinfo;

/*
 * 声明函数pstore_set_kmsg_bytes，用于设置内核消息的字节大小。
 */
extern void	pstore_set_kmsg_bytes(int);
/*
 * 声明函数pstore_get_records，用于获取存储的记录。
 */
extern void	pstore_get_records(int);
/*
 * 声明函数pstore_get_backend_records，用于从pstore后端获取记录。
 * 参数psi指向pstore_info结构，root是目录项的根，quiet用于控制输出。
 */
extern void	pstore_get_backend_records(struct pstore_info *psi,
					   struct dentry *root, int quiet);
/*
 * 声明函数pstore_put_backend_records，用于向pstore后端存储记录。
 * 参数psi指向pstore_info结构。
 */
extern int	pstore_put_backend_records(struct pstore_info *psi);
/*
 * 声明函数pstore_mkfile，用于在根目录项下创建一个文件，该文件包含pstore记录。
 * 参数root是目录项的根，record指向pstore_record结构。
 */
extern int	pstore_mkfile(struct dentry *root,
			      struct pstore_record *record);
/*
 * 声明函数pstore_record_init，用于初始化一个pstore记录。
 * 参数record指向pstore_record结构，psi指向pstore_info结构。
 */
extern void	pstore_record_init(struct pstore_record *record,
				   struct pstore_info *psi);

/* Called during pstore init/exit. */
/* 在pstore初始化和退出时调用。 */
/*
 * 声明函数pstore_init_fs，标记为__init，说明此函数仅在内核初始化时使用。
 * 此函数用于初始化pstore文件系统。
 */
int __init	pstore_init_fs(void);
/*
 * 声明函数pstore_exit_fs，标记为__exit，说明此函数仅在内核退出时使用。
 * 此函数用于退出pstore文件系统。
 */
void __exit	pstore_exit_fs(void);

#endif

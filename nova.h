/*
 * BRIEF DESCRIPTION
 *
 * Definitions for the NOVA filesystem.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */
#ifndef __NOVA_H
#define __NOVA_H

#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/buffer_head.h>
#include <linux/uio.h>
#include <linux/iomap.h>
#include <linux/crc32c.h>
#include <asm/tlbflush.h>
#include <linux/version.h>
#include <linux/pfn_t.h>
#include <linux/pagevec.h>

#include "nova_def.h"
#include "stats.h"

#define PAGE_SHIFT_2M 21
#define PAGE_SHIFT_1G 30


/*
 * Debug code
 */
#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

/* #define nova_dbg(s, args...)		pr_debug(s, ## args) */
#define nova_dbg(s, args ...)		pr_info(s, ## args)
#define nova_err(sb, s, args ...)	nova_error_mng(sb, s, ## args)
#define nova_warn(s, args ...)		pr_warn(s, ## args)
#define nova_info(s, args ...)		pr_info(s, ## args)

extern unsigned int nova_dbgmask;
#define NOVA_DBGMASK_MMAPHUGE	       (0x00000001)
#define NOVA_DBGMASK_MMAP4K	       (0x00000002)
#define NOVA_DBGMASK_MMAPVERBOSE       (0x00000004)
#define NOVA_DBGMASK_MMAPVVERBOSE      (0x00000008)
#define NOVA_DBGMASK_VERBOSE	       (0x00000010)
#define NOVA_DBGMASK_TRANSACTION       (0x00000020)

#define nova_dbg_mmap4k(s, args ...)		 \
	((nova_dbgmask & NOVA_DBGMASK_MMAP4K) ? nova_dbg(s, args) : 0)
#define nova_dbg_mmapv(s, args ...)		 \
	((nova_dbgmask & NOVA_DBGMASK_MMAPVERBOSE) ? nova_dbg(s, args) : 0)
#define nova_dbg_mmapvv(s, args ...)		 \
	((nova_dbgmask & NOVA_DBGMASK_MMAPVVERBOSE) ? nova_dbg(s, args) : 0)

#define nova_dbg_verbose(s, args ...)		 \
	((nova_dbgmask & NOVA_DBGMASK_VERBOSE) ? nova_dbg(s, ##args) : 0)
#define nova_dbgv(s, args ...)	nova_dbg_verbose(s, ##args)
#define nova_dbg_trans(s, args ...)		 \
	((nova_dbgmask & NOVA_DBGMASK_TRANSACTION) ? nova_dbg(s, ##args) : 0)

#define NOVA_ASSERT(x) do {\
			       if (!(x))\
				       nova_warn("assertion failed %s:%d: %s\n", \
			       __FILE__, __LINE__, #x);\
		       } while (0)

#define nova_set_bit		       __test_and_set_bit_le
#define nova_clear_bit		       __test_and_clear_bit_le
#define nova_find_next_zero_bit	       find_next_zero_bit_le

#define clear_opt(o, opt)	(o &= ~NOVA_MOUNT_ ## opt)
#define set_opt(o, opt)		(o |= NOVA_MOUNT_ ## opt)
#define test_opt(sb, opt)	(NOVA_SB(sb)->s_mount_opt & NOVA_MOUNT_ ## opt)

#define NOVA_LARGE_INODE_TABLE_SIZE    (0x200000)
/* NOVA size threshold for using 2M blocks for inode table */
#define NOVA_LARGE_INODE_TABLE_THREASHOLD    (0x20000000)
/*
 * nova inode flags
 *
 * NOVA_EOFBLOCKS_FL	There are blocks allocated beyond eof
 */
#define NOVA_EOFBLOCKS_FL      0x20000000
/* Flags that should be inherited by new inodes from their parent. */
#define NOVA_FL_INHERITED (FS_SECRM_FL | FS_UNRM_FL | FS_COMPR_FL | \
			    FS_SYNC_FL | FS_NODUMP_FL | FS_NOATIME_FL |	\
			    FS_COMPRBLK_FL | FS_NOCOMP_FL | \
			    FS_JOURNAL_DATA_FL | FS_NOTAIL_FL | FS_DIRSYNC_FL)
/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define NOVA_REG_FLMASK (~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
/* Flags that are appropriate for non-directories/regular files. */
#define NOVA_OTHER_FLMASK (FS_NODUMP_FL | FS_NOATIME_FL)
#define NOVA_FL_USER_VISIBLE (FS_FL_USER_VISIBLE | NOVA_EOFBLOCKS_FL)

/* IOCTLs */
#define	NOVA_PRINT_TIMING		0xBCD00010
#define	NOVA_CLEAR_STATS		0xBCD00011
#define	NOVA_PRINT_LOG			0xBCD00013
#define	NOVA_PRINT_LOG_BLOCKNODE	0xBCD00014
#define	NOVA_PRINT_LOG_PAGES		0xBCD00015
#define	NOVA_PRINT_FREE_LISTS		0xBCD00018


#define	READDIR_END			(ULONG_MAX)
#define	ANY_CPU				(65536)
#define	FREE_BATCH			(16)


extern int measure_timing;


extern unsigned int blk_type_to_shift[NOVA_BLOCK_TYPE_MAX];
extern unsigned int blk_type_to_size[NOVA_BLOCK_TYPE_MAX];


/* Mask out flags that are inappropriate for the given type of inode. */
static inline __le32 nova_mask_flags(umode_t mode, __le32 flags)
{
	flags &= cpu_to_le32(NOVA_FL_INHERITED);
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & cpu_to_le32(NOVA_REG_FLMASK);
	else
		return flags & cpu_to_le32(NOVA_OTHER_FLMASK);
}

static inline u32 nova_crc32c(u32 crc, const u8 *data, size_t len)
{
	return crc32c(crc, data, len);
}

static inline int memcpy_to_pmem_nocache(void *dst, const void *src,
	unsigned int size)
{
	int ret;

	ret = __copy_from_user_inatomic_nocache(dst, src, size);

	return ret;
}


/* assumes the length to be 4-byte aligned */
static inline void memset_nt(void *dest, uint32_t dword, size_t length)
{
	uint64_t dummy1, dummy2;
	uint64_t qword = ((uint64_t)dword << 32) | dword;

	asm volatile ("movl %%edx,%%ecx\n"
		"andl $63,%%edx\n"
		"shrl $6,%%ecx\n"
		"jz 9f\n"
		"1:	 movnti %%rax,(%%rdi)\n"
		"2:	 movnti %%rax,1*8(%%rdi)\n"
		"3:	 movnti %%rax,2*8(%%rdi)\n"
		"4:	 movnti %%rax,3*8(%%rdi)\n"
		"5:	 movnti %%rax,4*8(%%rdi)\n"
		"8:	 movnti %%rax,5*8(%%rdi)\n"
		"7:	 movnti %%rax,6*8(%%rdi)\n"
		"8:	 movnti %%rax,7*8(%%rdi)\n"
		"leaq 64(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 1b\n"
		"9:	movl %%edx,%%ecx\n"
		"andl $7,%%edx\n"
		"shrl $3,%%ecx\n"
		"jz 11f\n"
		"10:	 movnti %%rax,(%%rdi)\n"
		"leaq 8(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 10b\n"
		"11:	 movl %%edx,%%ecx\n"
		"shrl $2,%%ecx\n"
		"jz 12f\n"
		"movnti %%eax,(%%rdi)\n"
		"12:\n"
		: "=D"(dummy1), "=d" (dummy2)
		: "D" (dest), "a" (qword), "d" (length)
		: "memory", "rcx");
}


#include "super.h" // Remove when we factor out these and other functions.

/* Translate an offset the beginning of the Nova instance to a PMEM address.
 *
 * If this is part of a read-modify-write of the block,
 * nova_memunlock_block() before calling!
 */
static inline void *nova_get_block(struct super_block *sb, u64 block)
{
	struct nova_super_block *ps = nova_get_super(sb);

	return block ? ((void *)ps + block) : NULL;
}

static inline int nova_get_reference(struct super_block *sb, u64 block,
	void *dram, void **nvmm, size_t size)
{
	int rc;

	*nvmm = nova_get_block(sb, block);
	rc = memcpy_mcsafe(dram, *nvmm, size);
	return rc;
}


static inline u64
nova_get_addr_off(struct nova_sb_info *sbi, void *addr)
{
	NOVA_ASSERT((addr >= sbi->virt_addr) &&
			(addr < (sbi->virt_addr + sbi->initsize)));
	return (u64)(addr - sbi->virt_addr);
}

static inline u64
nova_get_block_off(struct super_block *sb, unsigned long blocknr,
		    unsigned short btype)
{
	return (u64)blocknr << PAGE_SHIFT;
}

static inline int nova_get_cpuid(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	return smp_processor_id() % sbi->cpus;
}

static inline u64 nova_get_epoch_id(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	return sbi->s_epoch_id;
}

#include "inode.h"

static inline int nova_get_head_tail(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih)
{
	struct nova_inode fake_pi;
	int rc;

	rc = memcpy_mcsafe(&fake_pi, pi, sizeof(struct nova_inode));
	if (rc)
		return rc;

	sih->i_blk_type = fake_pi.i_blk_type;
	sih->log_head = fake_pi.log_head;
	sih->log_tail = fake_pi.log_tail;

	return rc;
}

#include "log.h"

struct nova_range_node_lowhigh {
	__le64 range_low;
	__le64 range_high;
};

#define	RANGENODE_PER_PAGE	254

/* A range node can represent a range of pages/inodes, or a direntry node */
struct nova_range_node {
	struct rb_node node;
	union {
		/* Block, inode */
		struct {
			unsigned long range_low;
			unsigned long range_high;
		};
		/* Dir node */
		struct {
			unsigned long hash;
			void *direntry;
		};
	};
};

#include "bbuild.h"

struct inode_map {
	struct mutex		inode_table_mutex;
	struct rb_root		inode_inuse_tree;
	unsigned long		num_range_node_inode;
	struct nova_range_node *first_inode_range;
	int			allocated;
	int			freed;
};


/* Old entry is freeable if it is appended after the latest snapshot */
static inline int old_entry_freeable(struct super_block *sb, u64 epoch_id)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (epoch_id == sbi->s_epoch_id)
		return 1;

	return 0;
}

// BKDR String Hash Function
static inline unsigned long BKDRHash(const char *str, int length)
{
	unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
	unsigned long hash = 0;
	int i;

	for (i = 0; i < length; i++)
		hash = hash * seed + (*str++);

	/* READDIR_END is reserved as sentinel */
	if (hash == READDIR_END)
		hash--;

	return hash;
}

#include "balloc.h"

static inline struct nova_file_write_entry *
nova_get_or_lock_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr, int lock)
{
	struct nova_file_write_entry *entry;
	void **entryp;

	rcu_read_lock();
repeat:
	entry = NULL;
	entryp = radix_tree_lookup_slot(&sih->tree, blocknr);
	if (entryp) {
		entry = radix_tree_deref_slot(entryp);
		if (unlikely(!entry))
			goto out;

		if (radix_tree_exception(entry)) {
			if (radix_tree_deref_retry(entry))
				goto repeat;

			/* FIXME: What to do here? */
			entry = NULL;
			goto out;
		}

		if (lock) {
			if (!lock_write_entry(entry))
				goto repeat;
		} else {
			if (!get_write_entry(entry))
				goto repeat;
		}

		if (unlikely(entry != *entryp)) {
			put_write_entry(entry);
			goto repeat;
		}
	}
out:
	rcu_read_unlock();

	return entry;
}

static inline struct nova_file_write_entry *
nova_get_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr)
{
	return nova_get_or_lock_write_entry(sb, sih, blocknr, 0);
}

static inline struct nova_file_write_entry *
nova_lock_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr)
{
	return nova_get_or_lock_write_entry(sb, sih, blocknr, 1);
}

/*
 * Find data at a file offset (pgoff) in the data pointed to by a write log
 * entry.
 */
static inline unsigned long get_nvmm(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry, unsigned long pgoff)
{
	/* entry is already verified before this call and resides in dram
	 * or we can do memcpy_mcsafe here but have to avoid double copy and
	 * verification of the entry.
	 */
	if (entry->pgoff > pgoff || (unsigned long) entry->pgoff +
			(unsigned long) entry->num_pages <= pgoff) {
		struct nova_sb_info *sbi = NOVA_SB(sb);
		u64 curr;

		curr = nova_get_addr_off(sbi, entry);
		nova_dbg("Entry ERROR: inode %lu, curr 0x%llx, pgoff %lu, "
			"entry pgoff %llu, num %u, counter %d\n",
			sih->ino, curr, pgoff, entry->pgoff,
			entry->num_pages, entry->counter);
		nova_print_nova_log_pages(sb, sih);
		nova_print_curr_log_page(sb, curr);
		NOVA_ASSERT(0);
		dump_stack();
	}

	return (unsigned long) (entry->block >> PAGE_SHIFT) + pgoff
		- entry->pgoff;
}

static inline unsigned long
nova_get_numblocks(unsigned short btype)
{
	unsigned long num_blocks;

	if (btype == NOVA_BLOCK_TYPE_4K) {
		num_blocks = 1;
	} else if (btype == NOVA_BLOCK_TYPE_2M) {
		num_blocks = 512;
	} else {
		//btype == NOVA_BLOCK_TYPE_1G
		num_blocks = 0x40000;
	}
	return num_blocks;
}

static inline unsigned long
nova_get_blocknr(struct super_block *sb, u64 block, unsigned short btype)
{
	return block >> PAGE_SHIFT;
}


/* ====================================================== */
/* ==============  Function prototypes  ================= */
/* ====================================================== */

/* dax.c */
int nova_handle_head_tail_blocks(struct super_block *sb,
	struct inode *inode, loff_t pos, size_t count, void *kmem);
int nova_commit_writes_to_log(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, struct list_head *head, unsigned long new_blocks);
int nova_cleanup_incomplete_write(struct super_block *sb,
	struct nova_inode_info_header *sih, struct list_head *head);
void nova_init_file_write_item(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_item *item,
	u64 epoch_id, u64 pgoff, int num_pages, u64 blocknr, u32 time,
	u64 file_size);
unsigned long nova_check_existing_entry(struct super_block *sb,
	struct inode *inode, unsigned long num_blocks, unsigned long start_blk,
	struct nova_file_write_entry **ret_entry,
	int check_next, u64 epoch_id,
	int *inplace);
ssize_t nova_inplace_file_write(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos);
ssize_t do_nova_inplace_file_write(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos);

extern const struct iomap_ops nova_iomap_ops;
extern const struct vm_operations_struct nova_dax_vm_ops;


/* dir.c */
extern const struct file_operations nova_dir_operations;
int nova_insert_dir_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name,
	int namelen, struct nova_dentry *direntry);
int nova_remove_dir_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name, int namelen,
	int replay, struct nova_dentry **create_dentry);
void nova_delete_dir_tree(struct super_block *sb,
	struct nova_inode_info_header *sih);
struct nova_dentry *nova_find_dentry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len);
int nova_append_dir_init_entries(struct super_block *sb,
	struct nova_inode *pi, u64 self_ino, u64 parent_ino, u64 epoch_id);
int nova_add_dentry(struct dentry *dentry, u64 ino, int inc_link,
	struct nova_inode_update *update, u64 epoch_id);
int nova_remove_dentry(struct dentry *dentry, int dec_link,
	struct nova_inode_update *update, u64 epoch_id);

/* file.c */
extern const struct file_operations nova_dax_file_operations;
extern const struct inode_operations nova_file_inode_operations;


/* gc.c */
int nova_inode_log_fast_gc(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	u64 curr_tail, u64 new_block, int num_pages,
	int force_thorough);

/* ioctl.c */
extern long nova_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
extern long nova_compat_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg);
#endif

/* namei.c */
extern const struct inode_operations nova_dir_inode_operations;
extern const struct inode_operations nova_special_inode_operations;
extern struct dentry *nova_get_parent(struct dentry *child);

/* procfs.c */
extern const char *proc_dirname;
extern struct proc_dir_entry *nova_proc_root;
void nova_procfs_init(struct super_block *sb);
void nova_procfs_exit(struct super_block *sb);

/* rebuild.c */
int nova_rebuild_dir_inode_tree(struct super_block *sb,
	struct nova_inode *pi, u64 pi_addr,
	struct nova_inode_info_header *sih);
int nova_rebuild_inode(struct super_block *sb, struct nova_inode_info *si,
	u64 ino, u64 pi_addr, int rebuild_dir);

/* symlink.c */
int nova_block_symlink(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, const char *symname, int len, u64 epoch_id);
extern const struct inode_operations nova_symlink_inode_operations;

/* stats.c */
void nova_get_timing_stats(void);
void nova_get_IO_stats(void);
void nova_print_timing_stats(struct super_block *sb);
void nova_clear_stats(struct super_block *sb);
void nova_print_inode(struct nova_inode *pi);
void nova_print_inode_log(struct super_block *sb, struct inode *inode);
void nova_print_inode_log_pages(struct super_block *sb, struct inode *inode);
int nova_check_inode_logs(struct super_block *sb, struct nova_inode *pi);
void nova_print_free_lists(struct super_block *sb);

#endif /* __NOVA_H */

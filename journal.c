/*
 * NOVA journaling facility.
 *
 * This file contains journaling code to guarantee the atomicity of directory
 * operations that span multiple inodes (unlink, rename, etc).
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include "nova.h"

/**************************** Lite journal ******************************/

static inline void nova_print_lite_transaction(struct nova_lite_journal_entry *entry)
{
	nova_dbg("Entry %p: Type %llu, data1 0x%llx, data2 0x%llx\n, "
			"checksum %u\n", entry, entry->type,
			entry->data1, entry->data2, entry->csum);
}

static inline int nova_update_entry_checksum(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u32 crc = 0;

	crc = crc32c(~0, (__u8 *)entry,
			(sizeof(struct nova_lite_journal_entry) - sizeof(__le32)));

	entry->csum = cpu_to_le32(crc);
	return 0;
}

static inline int nova_check_entry_checksum(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u32 crc = 0;

	crc = crc32c(~0, (__u8 *)entry,
			(sizeof(struct nova_lite_journal_entry) - sizeof(__le32)));

	if (entry->csum == cpu_to_le32(crc))
		return 0;
	else
		return 1;
}

static inline u64 next_lite_journal(u64 curr_p)
{
	size_t size = sizeof(struct nova_lite_journal_entry);

	/* One page holds 128 entries with cacheline size */
	if ((curr_p & (PAGE_SIZE - 1)) + size >= PAGE_SIZE)
		return (curr_p & PAGE_MASK);

	return curr_p + size;
}

static int nova_check_journal_entries(struct super_block *sb,
	struct ptr_pair *pair)
{
	struct nova_lite_journal_entry *entry;
	u64 temp;
	int ret;

	temp = pair->journal_head;
	while (temp != pair->journal_tail) {
		entry = (struct nova_lite_journal_entry *)nova_get_block(sb, temp);
		ret = nova_check_entry_checksum(sb, entry);
		if (ret) {
			nova_dbg("Entry %p checksum failure\n", entry);
			nova_print_lite_transaction(entry);
			return ret;
		}
		temp = next_lite_journal(temp);
	}

	return 0;
}

/**************************** Journal Recovery ******************************/

static void nova_recover_journal_inode(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	struct nova_inode *pi, *alter_pi;
	u64 pi_addr, alter_pi_addr;

	pi_addr = le64_to_cpu(entry->data1);
	alter_pi_addr = le64_to_cpu(entry->data2);

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);
	alter_pi = (struct nova_inode *)nova_get_block(sb, alter_pi_addr);

	memcpy_to_pmem_nocache(pi, alter_pi, sizeof(struct nova_inode));
}

static void nova_recover_journal_entry(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u64 addr, value;

	addr = le64_to_cpu(entry->data1);
	value = le64_to_cpu(entry->data2);

	*(u64 *)nova_get_block(sb, addr) = (u64)value;
	nova_flush_buffer((void *)nova_get_block(sb, addr), CACHELINE_SIZE, 0);
}

static void nova_undo_lite_journal_entry(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u64 type;

	type = le64_to_cpu(entry->type);

	switch (type) {
		case JOURNAL_INODE:
			nova_recover_journal_inode(sb, entry);
			break;
		case JOURNAL_ENTRY:
			nova_recover_journal_entry(sb, entry);
			break;
		default:
			nova_dbg("%s: unknown data type %llu\n",
					__func__, type);
			break;
	}
}

static int nova_recover_lite_journal(struct super_block *sb,
	struct ptr_pair *pair)
{
	struct nova_lite_journal_entry *entry;
	u64 temp;

	temp = pair->journal_head;
	while (temp != pair->journal_tail) {
		entry = (struct nova_lite_journal_entry *)nova_get_block(sb, temp);
		nova_undo_lite_journal_entry(sb, entry);
		temp = next_lite_journal(temp);
	}

	pair->journal_tail = pair->journal_head;
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);

	return 0;
}

/**************************** Create/commit ******************************/

static int nova_append_inode_journal(struct super_block *sb,
	struct nova_lite_journal_entry *entry, struct inode *inode)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	entry->type = cpu_to_le64(JOURNAL_INODE);
	entry->padding = 0;
	entry->data1 = cpu_to_le64(sih->pi_addr);
	entry->data2 = cpu_to_le64(sih->alter_pi_addr);
	return nova_update_entry_checksum(sb, entry);
}

static int nova_append_entry_journal(struct super_block *sb,
	struct nova_lite_journal_entry *entry, u64 *field)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 addr = (u64)nova_get_addr_off(sbi, field);

	entry->type = cpu_to_le64(JOURNAL_ENTRY);
	entry->padding = 0;
	entry->data1 = cpu_to_le64(addr);
	entry->data2 = cpu_to_le64(*field);
	return nova_update_entry_checksum(sb, entry);
}

u64 nova_create_inode_transaction(struct super_block *sb,
	struct inode *inode1, struct inode *inode2, int cpu)
{
	struct ptr_pair *pair;
	struct nova_lite_journal_entry *entry;
	u64 new_tail, temp;;

	pair = nova_get_journal_pointers(sb, cpu);
	if (!pair || pair->journal_head == 0 ||
			pair->journal_head != pair->journal_tail)
		BUG();

	temp = pair->journal_head;
	entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);

	nova_append_inode_journal(sb, entry, inode1);

	temp = next_lite_journal(temp);
	entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);
	nova_append_inode_journal(sb, entry, inode2);

	new_tail = next_lite_journal(temp);
	pair->journal_tail = new_tail;
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);

	return new_tail;
}

u64 nova_create_rename_transaction(struct super_block *sb,
	struct inode *old_inode, struct inode *old_dir, struct inode *new_inode,
	struct inode *new_dir, u64 *father_ino, int cpu)
{
	struct ptr_pair *pair;
	struct nova_lite_journal_entry *entry;
	u64 new_tail, temp;;

	pair = nova_get_journal_pointers(sb, cpu);
	if (!pair || pair->journal_head == 0 ||
			pair->journal_head != pair->journal_tail)
		BUG();

	temp = pair->journal_head;
	entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);

	nova_append_inode_journal(sb, entry, old_inode);

	temp = next_lite_journal(temp);

	entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);
	nova_append_inode_journal(sb, entry, old_dir);

	if (new_inode) {
		temp = next_lite_journal(temp);

		entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);
		nova_append_inode_journal(sb, entry, new_inode);
	}

	if (new_dir) {
		temp = next_lite_journal(temp);

		entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);
		nova_append_inode_journal(sb, entry, new_dir);
	}

	if (father_ino) {
		temp = next_lite_journal(temp);

		entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							temp);
		nova_append_entry_journal(sb, entry, father_ino);
	}

	new_tail = next_lite_journal(temp);
	pair->journal_tail = new_tail;
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);

	return new_tail;
}

void nova_commit_lite_transaction(struct super_block *sb, u64 tail, int cpu)
{
	struct ptr_pair *pair;

	pair = nova_get_journal_pointers(sb, cpu);
	if (!pair || pair->journal_tail != tail)
		BUG();

	pair->journal_head = tail;
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);
}

/**************************** Initialization ******************************/

int nova_lite_journal_soft_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct ptr_pair *pair;
	int i;
	int ret;

	sbi->journal_locks = kzalloc(sbi->cpus * sizeof(spinlock_t),
					GFP_KERNEL);
	if (!sbi->journal_locks)
		return -ENOMEM;

	for (i = 0; i < sbi->cpus; i++)
		spin_lock_init(&sbi->journal_locks[i]);

	for (i = 0; i < sbi->cpus; i++) {
		pair = nova_get_journal_pointers(sb, i);
		if (pair->journal_head == pair->journal_tail)
			continue;

		/* Ensure all entries are genuine */
		ret = nova_check_journal_entries(sb, pair);
		if (ret) {
			nova_err(sb, "Journal %d checksum failure\n", i);
			ret = -EINVAL;
			break;
		}

		ret = nova_recover_lite_journal(sb, pair);
	}

	return ret;
}

int nova_lite_journal_hard_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode fake_pi;
	struct ptr_pair *pair;
	unsigned long blocknr = 0;
	int allocated;
	int i;
	u64 block;

	fake_pi.nova_ino = NOVA_LITEJOURNAL_INO;
	fake_pi.i_blk_type = NOVA_BLOCK_TYPE_4K;

	for (i = 0; i < sbi->cpus; i++) {
		pair = nova_get_journal_pointers(sb, i);
		if (!pair)
			return -EINVAL;

		allocated = nova_new_log_blocks(sb, &fake_pi, &blocknr, 1, 1);
		nova_dbg_verbose("%s: allocate log @ 0x%lx\n", __func__,
							blocknr);
		if (allocated != 1 || blocknr == 0)
			return -ENOSPC;

		block = nova_get_block_off(sb, blocknr, NOVA_BLOCK_TYPE_4K);
		pair->journal_head = pair->journal_tail = block;
		nova_flush_buffer(pair, CACHELINE_SIZE, 0);
	}

	PERSISTENT_BARRIER();
	return nova_lite_journal_soft_init(sb);
}


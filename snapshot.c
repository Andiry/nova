/*
 * BRIEF DESCRIPTION
 *
 * Snapshot support
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "nova.h"

static inline u64 next_list_page(u64 curr_p)
{
	void *curr_addr = (void *)curr_p;
	unsigned long page_tail = ((unsigned long)curr_addr & ~INVALID_MASK)
					+ LAST_ENTRY;
	return ((struct nova_inode_page_tail *)page_tail)->next_page;
}

/* Reuse the inode log page structure */
static inline void nova_set_next_link_page_address(struct super_block *sb,
	struct nova_inode_log_page *curr_page, u64 next_page)
{
	curr_page->page_tail.next_page = next_page;
}

int nova_alloc_snapshot_info(struct super_block *sb, u64 trans_id)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_info *snapshot_info;
	struct snapshot_list *snapshot_list;
	unsigned long new_page = 0;
	int i;

	snapshot_info = kzalloc(sizeof(struct snapshot_info), GFP_KERNEL);
	if (!snapshot_info)
		return -ENOMEM;

	snapshot_info->trans_id = trans_id;
	snapshot_info->lists = kzalloc(sbi->cpus * sizeof(struct snapshot_list),
							GFP_KERNEL);

	if (!snapshot_info->lists) {
		kfree(snapshot_info);
		return -ENOMEM;
	}

	for (i = 0; i < sbi->cpus; i++) {
		snapshot_list = &snapshot_info->lists[i];
		mutex_init(&snapshot_list->list_mutex);
		new_page = (unsigned long)kmalloc(PAGE_SIZE,
							GFP_KERNEL);
		/* Aligned to PAGE_SIZE */
		if (!new_page || ENTRY_LOC(new_page))
			goto fail;
		nova_set_next_link_page_address(sb, (void *)new_page, 0);
		snapshot_list->tail = snapshot_list->head = new_page;
		snapshot_list->num_pages = 1;
	}

	return 0;

fail:
	kfree((void *)new_page);
	for (i = 0; i < sbi->cpus; i++) {
		snapshot_list = &snapshot_info->lists[i];
		if (snapshot_list->head)
			kfree((void *)snapshot_list->head);
	}

	kfree(snapshot_info->lists);
	kfree(snapshot_info);
	return -ENOMEM;
}

static void nova_write_list_entry(struct super_block *sb,
	struct snapshot_list *list, u64 curr_p, void *entry, size_t size)
{
	if (is_last_entry(curr_p, size)) {
		nova_err(sb, "%s: write to page end? curr 0x%llx, size %lu\n",
				__func__, curr_p, size);
		return;
	}

	memcpy((void *)curr_p, entry, size);
	list->tail = curr_p + size;
}

int nova_append_snapshot_list_entry(struct super_block *sb,
	struct snapshot_info *info, void *entry, size_t size)
{
	struct snapshot_list *list;
	struct nova_inode_log_page *curr_page;
	u64 curr_block;
	int cpuid;
	u64 curr_p;
	u64 new_page = 0;

	cpuid = smp_processor_id();
	list = &info->lists[cpuid];

retry:
	mutex_lock(&list->list_mutex);
	curr_p = list->tail;

	if (new_page) {
		/* Link prev block and newly allocated page */
		curr_block = BLOCK_OFF(curr_p);
		curr_page = (struct nova_inode_log_page *)curr_block;
		nova_set_next_link_page_address(sb, curr_page, new_page);
		list->num_pages++;
	}

	if ((is_last_entry(curr_p, size) && next_list_page(curr_p) == 0)) {
		nova_set_entry_type((void *)curr_p, NEXT_PAGE);
		if (new_page == 0) {
			mutex_unlock(&list->list_mutex);
			new_page = (unsigned long)kmalloc(PAGE_SIZE,
						GFP_KERNEL);
			if (!new_page || ENTRY_LOC(new_page)) {
				kfree((void *)new_page);
				nova_err(sb, "%s: allocation failed\n",
						__func__);
				return -ENOMEM;
			}
			nova_set_next_link_page_address(sb,
						(void *)new_page, 0);
			goto retry;
		}
	}

	if (is_last_entry(curr_p, size)) {
		nova_set_entry_type((void *)curr_p, NEXT_PAGE);
		curr_p = next_list_page(curr_p);
	}

	nova_write_list_entry(sb, list, curr_p, entry, size);
	mutex_unlock(&list->list_mutex);

	return 0;
}

int nova_encounter_recover_snapshot(struct super_block *sb, void *addr,
	u8 type)
{
	struct nova_dentry *dentry;
	struct nova_setattr_logentry *attr_entry;
	struct nova_link_change_entry *linkc_entry;
	struct nova_file_write_entry *fw_entry;
	int ret = 0;

	switch (type) {
		case SET_ATTR:
			attr_entry = (struct nova_setattr_logentry *)addr;
			if (pass_recover_snapshot(sb, attr_entry->trans_id))
				ret = 1;
			break;
		case LINK_CHANGE:
			linkc_entry = (struct nova_link_change_entry *)addr;
			if (pass_recover_snapshot(sb, linkc_entry->trans_id))
				ret = 1;
			break;
		case DIR_LOG:
			dentry = (struct nova_dentry *)addr;
			if (pass_recover_snapshot(sb, dentry->trans_id))
				ret = 1;
			break;
		case FILE_WRITE:
			fw_entry = (struct nova_file_write_entry *)addr;
			if (pass_recover_snapshot(sb, fw_entry->trans_id))
				ret = 1;
			break;
		default:
			break;
	}

	return ret;
}

int nova_restore_snapshot_table(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_table *snapshot_table;
	int i, index;
	u64 prev_trans_id, recover_trans_id;

	snapshot_table = nova_get_snapshot_table(sb);

	if (!snapshot_table)
		return -EINVAL;

	prev_trans_id = 0;
	for (i = 0; i < SNAPSHOT_TABLE_SIZE; i++) {
		/* Find first unused slot */
		if (snapshot_table->entries[i].trans_id == 0) {
			sbi->curr_snapshot = i;
			break;
		}

		if (snapshot_table->entries[i].trans_id < prev_trans_id) {
			sbi->curr_snapshot = i;
			break;
		}

		prev_trans_id = snapshot_table->entries[i].trans_id;
		sbi->latest_snapshot_trans_id = prev_trans_id;
	}

	if (i == SNAPSHOT_TABLE_SIZE)
		goto fail;

	if (sbi->recover_snapshot) {
		index = sbi->recover_snapshot_index;
		if (index < 0 || index >= SNAPSHOT_TABLE_SIZE) {
			nova_dbg("%s: recover invalid snapshot %d\n",
					__func__, index);
			sbi->recover_snapshot = 0;
			goto fail;
		}

		recover_trans_id = snapshot_table->entries[index].trans_id;
		if (recover_trans_id == 0) {
			nova_dbg("%s: recover invalid snapshot %d\n",
					__func__, index);
			sbi->recover_snapshot = 0;
			goto fail;
		}

		sbi->recover_snapshot_trans_id = recover_trans_id;
		nova_dbg("recover snapshot %d\n", index);
	}

	return 0;
fail:
	nova_dbg("%s: failed\n", __func__);
	return -EINVAL;
}

int nova_print_snapshot_table(struct super_block *sb, struct seq_file *seq)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_table *snapshot_table;
	int i, curr, count = 0;
	u64 trans_id, timestamp;
	u64 sec, nsec;

	snapshot_table = nova_get_snapshot_table(sb);

	if (!snapshot_table)
		return -EINVAL;

	seq_printf(seq, "========== NOVA snapshot table ==========\n");
	seq_printf(seq, "Index\tTrans ID\tTime\n");

	/*  Print in reverse order */
	curr = sbi->curr_snapshot - 1;
	if (curr < 0)
		curr += SNAPSHOT_TABLE_SIZE;

	for (i = 0; i < SNAPSHOT_TABLE_SIZE; i++) {
		if (snapshot_table->entries[curr].timestamp) {
			trans_id = snapshot_table->entries[curr].trans_id;
			timestamp = snapshot_table->entries[curr].timestamp;
			sec = timestamp >> 32;
			nsec = timestamp & 0xFFFFFFFF;
			seq_printf(seq, "%d\t%llu\t\t%llu.%llu\n", curr,
					trans_id, sec, nsec);
			count++;
		}

		curr--;
		if (curr < 0)
			curr += SNAPSHOT_TABLE_SIZE;
	}

	seq_printf(seq, "=========== Total %d snapshots ===========\n", count);
	return 0;
}

int nova_create_snapshot(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *super = nova_get_super(sb);
	struct snapshot_table *snapshot_table;
	u64 timestamp = 0;
	u64 trans_id;

	snapshot_table = nova_get_snapshot_table(sb);

	if (!snapshot_table)
		return -EINVAL;

	mutex_lock(&sbi->s_lock);
	trans_id = atomic64_read(&super->s_trans_id);
	timestamp = (CURRENT_TIME_SEC.tv_sec << 32) |
			(CURRENT_TIME_SEC.tv_nsec);
	snapshot_table->entries[sbi->curr_snapshot].trans_id = trans_id;
	snapshot_table->entries[sbi->curr_snapshot].timestamp = timestamp;
	nova_flush_buffer(&snapshot_table->entries[sbi->curr_snapshot],
				CACHELINE_SIZE, 1);
	sbi->num_snapshots++;
	sbi->curr_snapshot++;
	sbi->latest_snapshot_trans_id = trans_id;
	if (sbi->curr_snapshot >= SNAPSHOT_TABLE_SIZE)
		sbi->curr_snapshot -= SNAPSHOT_TABLE_SIZE;
	mutex_unlock(&sbi->s_lock);

	return 0;
}

static inline bool goto_next_list_page(struct super_block *sb, u64 curr_p)
{
	void *addr;
	u8 type;

	/* Each kind of entry takes at least 32 bytes */
	if (ENTRY_LOC(curr_p) + 32 > LAST_ENTRY)
		return true;

	addr = (void *)curr_p;
	type = nova_get_entry_type(addr);
	if (type == NEXT_PAGE)
		return true;

	return false;
}

static int nova_delete_snapshot_list_entries(struct super_block *sb,
	struct snapshot_list *list)
{
	struct snapshot_file_write_entry *w_entry = NULL;
	struct snapshot_inode_entry *i_entry = NULL;
	struct nova_inode fake_pi;
	void *addr;
	u64 curr_p;
	u8 type;

	fake_pi.nova_ino = 0;
	fake_pi.i_blk_type = 0;

	curr_p = list->head;
	nova_dbg_verbose("Snapshot list head 0x%llx, tail 0x%lx\n",
				curr_p, list->tail);
	if (curr_p == 0 && list->tail == 0)
		return 0;

	while (curr_p != list->tail) {
		if (goto_next_list_page(sb, curr_p))
			curr_p = next_list_page(curr_p);

		if (curr_p == 0) {
			nova_err(sb, "Snapshot list is NULL!\n");
			BUG();
		}

		addr = (void *)curr_p;
		type = nova_get_entry_type(addr);

		switch (type) {
			case SS_INODE:
				i_entry = (struct snapshot_inode_entry *)addr;
//				nova_delete_dead_inode(sb, i_entry->nova_ino);
				curr_p += sizeof(struct snapshot_inode_entry);
				continue;
			case SS_FILE_WRITE:
				w_entry =
					(struct snapshot_file_write_entry *)addr;
				nova_free_data_blocks(sb, &fake_pi,
							w_entry->nvmm,
							w_entry->num_pages);
				curr_p += sizeof(struct snapshot_file_write_entry);
				continue;
			default:
				nova_err(sb, "unknown type %d, 0x%llx\n",
							type, curr_p);
				NOVA_ASSERT(0);
				curr_p += sizeof(struct snapshot_file_write_entry);
				continue;
		}
	}

	return 0;
}

static int nova_delete_snapshot_list_pages(struct super_block *sb,
	struct snapshot_list *list)
{
	struct nova_inode_log_page *curr_page;
	u64 curr_block = list->head;
	int freed = 0;

	while (curr_block) {
		if (curr_block & INVALID_MASK) {
			nova_dbg("%s: ERROR: invalid block %llu\n",
					__func__, curr_block);
			break;
		}
		curr_page = (struct nova_inode_log_page *)curr_block;
		curr_block = curr_page->page_tail.next_page;
		kfree(curr_page);
		freed++;
	}

	return freed;
}

static int nova_delete_snapshot_list(struct super_block *sb,
	struct snapshot_list *list)
{
	nova_delete_snapshot_list_entries(sb, list);
	nova_delete_snapshot_list_pages(sb, list);
	return 0;
}

static int nova_delete_snapshot_info(struct super_block *sb,
	struct snapshot_info *info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_list *list;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		list = &info->lists[i];
		mutex_lock(&list->list_mutex);
		nova_delete_snapshot_list(sb, list);
		mutex_unlock(&list->list_mutex);
	}

	kfree(info->lists);
	kfree(info);
	return 0;
}

static int nova_link_to_next_snapshot(struct super_block *sb,
	struct snapshot_info *prev_info, struct snapshot_info *next_info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_list *prev_list, *next_list;
	struct nova_inode_log_page *curr_page;
	u64 curr_block;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		prev_list = &prev_info->lists[i];
		next_list = &next_info->lists[i];

		mutex_lock(&prev_list->list_mutex);
		mutex_lock(&next_list->list_mutex);

		/* Link the prev lists to the head of next lists */
		curr_block = BLOCK_OFF(prev_list->tail);
		curr_page = (struct nova_inode_log_page *)curr_block;
		nova_set_next_link_page_address(sb, curr_page, next_list->head);

		next_list->head = prev_list->head;
		next_list->num_pages += prev_list->num_pages;

		mutex_unlock(&next_list->list_mutex);
		mutex_unlock(&prev_list->list_mutex);
	}

	/* FIXME: Start a background thread to free freeable items */
	return 0;
}

/* FIXME: 1) Snapshot hole 2) latest snapshot trans ID update */
int nova_delete_snapshot(struct super_block *sb, int index)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_table *snapshot_table;

	snapshot_table = nova_get_snapshot_table(sb);

	if (!snapshot_table)
		return -EINVAL;

	if (index < 0 || index >= SNAPSHOT_TABLE_SIZE) {
		nova_dbg("%s: Invalid snapshot number %d\n", __func__, index);
		return -EINVAL;
	}

	mutex_lock(&sbi->s_lock);
	snapshot_table->entries[index].trans_id = 0;
	snapshot_table->entries[index].timestamp = 0;
	sbi->num_snapshots--;
	nova_flush_buffer(&snapshot_table->entries[index],
				CACHELINE_SIZE, 1);
	mutex_unlock(&sbi->s_lock);

	return 0;
}

static void nova_copy_snapshot_list(struct super_block *sb,
	struct snapshot_list *list, u64 new_block)
{
	struct nova_inode_log_page *nvmm_page, *dram_page;
	void *curr_nvmm_addr;
	u64 curr_nvmm_block;
	u64 prev_nvmm_block;
	u64 curr_dram_addr;
	unsigned long i;

	curr_dram_addr = list->head;
	curr_nvmm_block = new_block;
	curr_nvmm_addr = nova_get_block(sb, curr_nvmm_block);

	for (i = 0; i < list->num_pages; i++) {
		/* Leave next_page field alone */
		memcpy_to_pmem_nocache(curr_nvmm_addr, (void *)curr_dram_addr,
						LAST_ENTRY);

		nvmm_page = (struct nova_inode_log_page *)curr_nvmm_addr;
		dram_page = (struct nova_inode_log_page *)curr_dram_addr;
		prev_nvmm_block = curr_nvmm_block;
		curr_nvmm_block = nvmm_page->page_tail.next_page;
		curr_nvmm_addr = nova_get_block(sb, curr_nvmm_block);
		curr_dram_addr = dram_page->page_tail.next_page;
	}
}

void nova_save_snapshot_info(struct super_block *sb, struct snapshot_info *info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode fake_pi;
	struct snapshot_list *list;
	unsigned long num_pages;
	int i;
	u64 new_block;
	int allocated;

	fake_pi.nova_ino = 0;
	fake_pi.i_blk_type = 0;

	for (i = 0; i < sbi->cpus; i++) {
		list = &info->lists[i];
		num_pages = list->num_pages;
		allocated = nova_allocate_inode_log_pages(sb, &fake_pi,
					num_pages, &new_block);
		if (allocated != num_pages) {
			nova_dbg("Error saving snapshot list: %d\n", allocated);
			return;
		}
		nova_copy_snapshot_list(sb, list, new_block);
	}

}


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

static inline int nova_rbtree_compare_snapshot_info(struct snapshot_info *curr,
	u64 trans_id)
{
	if (trans_id < curr->trans_id)
		return -1;
	if (trans_id > curr->trans_id)
		return 1;

	return 0;
}

static int nova_find_target_snapshot_info(struct super_block *sb,
	u64 trans_id, struct snapshot_info **ret_info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct rb_root *tree;
	struct snapshot_info *curr = NULL;
	struct rb_node *temp;
	int compVal;
	int ret = 0;

	tree = &sbi->snapshot_info_tree;
	temp = tree->rb_node;

	while (temp) {
		curr = container_of(temp, struct snapshot_info, node);
		compVal = nova_rbtree_compare_snapshot_info(curr, trans_id);

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			ret = 1;
			break;
		}
	}

	if (!curr)
		return -EINVAL;

	if (curr->trans_id < trans_id) {
		temp = rb_next(&curr->node);
		if (!temp) {
			nova_dbg("%s: failed to find target snapshot info\n",
					__func__);
			BUG();
			return -EINVAL;
		}
		curr = container_of(temp, struct snapshot_info, node);
	}

	*ret_info = curr;
	return ret;
}

static struct snapshot_info *
nova_find_adjacent_snapshot_info(struct super_block *sb,
	struct snapshot_info *info, int next)
{
	struct snapshot_info *ret_info = NULL;
	struct rb_node *temp;

	if (next)
		temp = rb_next(&info->node);
	else
		temp = rb_prev(&info->node);

	if (!temp)
		return ret_info;

	ret_info = container_of(temp, struct snapshot_info, node);
	return ret_info;
}

static int nova_insert_snapshot_info(struct super_block *sb,
	struct snapshot_info *info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct rb_root *tree;
	struct snapshot_info *curr;
	struct rb_node **temp, *parent;
	int compVal;

	tree = &sbi->snapshot_info_tree;
	temp = &(tree->rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct snapshot_info, node);
		compVal = nova_rbtree_compare_snapshot_info(curr,
						info->trans_id);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		} else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		} else {
			/* Do not insert snapshot with same trans ID */
			return -EEXIST;
		}
	}

	rb_link_node(&info->node, parent, temp);
	rb_insert_color(&info->node, tree);

	return 0;
}

/* Reuse the inode log page structure */
static inline void nova_set_link_page_trans_id(struct super_block *sb,
	struct nova_inode_log_page *curr_page, u64 trans_id)
{
	curr_page->page_tail.trans_id = trans_id;
}

/* Reuse the inode log page structure */
static inline void nova_set_next_link_page_address(struct super_block *sb,
	struct nova_inode_log_page *curr_page, u64 next_page)
{
	curr_page->page_tail.next_page = next_page;
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

	fake_pi.nova_ino = NOVA_SNAPSHOT_INO;
	fake_pi.i_blk_type = 0;

	curr_p = list->head;
	nova_dbg_verbose("Snapshot list head 0x%llx, tail 0x%lx\n",
				curr_p, list->tail);
	if (curr_p == 0 && list->tail == 0)
		return 0;

	while (curr_p != list->tail) {
		if (goto_next_list_page(sb, curr_p)) {
			curr_p = next_list_page(curr_p);
			if (curr_p == list->tail)
				break;
		}

		if (curr_p == 0) {
			nova_err(sb, "Snapshot list is NULL!\n");
			BUG();
		}

		addr = (void *)curr_p;
		type = nova_get_entry_type(addr);

		switch (type) {
			case SS_INODE:
				i_entry = (struct snapshot_inode_entry *)addr;
				if (i_entry->deleted == 0)
					nova_delete_dead_inode(sb,
							i_entry->nova_ino);
				curr_p += sizeof(struct snapshot_inode_entry);
				continue;
			case SS_FILE_WRITE:
				w_entry = (struct snapshot_file_write_entry *)addr;
				if (w_entry->deleted == 0)
					nova_free_data_blocks(sb, &fake_pi,
							w_entry->nvmm,
							w_entry->num_pages);
				curr_p += sizeof(struct snapshot_file_write_entry);
				continue;
			default:
				nova_err(sb, "unknown type %d, 0x%llx, "
						"tail 0x%llx\n",
						type, curr_p, list->tail);
				NOVA_ASSERT(0);
				curr_p += sizeof(struct snapshot_file_write_entry);
				continue;
		}
	}

	return 0;
}

static inline int nova_background_clean_inode_entry(struct super_block *sb,
	struct snapshot_inode_entry *i_entry, u64 trans_id)
{
	if (i_entry->deleted == 0 && i_entry->delete_trans_id <= trans_id) {
		nova_delete_dead_inode(sb, i_entry->nova_ino);
		i_entry->deleted = 1;
	}

	return 0;
}

static inline int nova_background_clean_write_entry(struct super_block *sb,
	struct snapshot_file_write_entry *w_entry,
	struct nova_inode *fake_pi, u64 trans_id)
{
	if (w_entry->deleted == 0 && w_entry->delete_trans_id <= trans_id) {
		nova_free_data_blocks(sb, fake_pi, w_entry->nvmm,
					w_entry->num_pages);
		w_entry->deleted = 1;
	}

	return 0;
}

static int nova_background_clean_snapshot_list(struct super_block *sb,
	struct snapshot_list *list, u64 trans_id)
{
	struct nova_inode_log_page *curr_page;
	struct nova_inode fake_pi;
	void *addr;
	u64 curr_p;
	u8 type;

	fake_pi.nova_ino = NOVA_SNAPSHOT_INO;
	fake_pi.i_blk_type = 0;

	curr_p = list->head;
	nova_dbg_verbose("Snapshot list head 0x%llx, tail 0x%lx\n",
				curr_p, list->tail);
	if (curr_p == 0 && list->tail == 0)
		return 0;

	curr_page = (struct nova_inode_log_page *)curr_p;
	while (curr_page->page_tail.trans_id < trans_id &&
					curr_p != list->tail) {
		if (goto_next_list_page(sb, curr_p)) {
			curr_p = next_list_page(curr_p);
			if (curr_p == list->tail)
				break;
			curr_page = (struct nova_inode_log_page *)curr_p;
			if (curr_page->page_tail.trans_id == trans_id)
				break;
		}

		if (curr_p == 0) {
			nova_err(sb, "Snapshot list is NULL!\n");
			BUG();
		}

		addr = (void *)curr_p;
		type = nova_get_entry_type(addr);

		switch (type) {
			case SS_INODE:
				nova_background_clean_inode_entry(sb, addr,
							trans_id);
				curr_p += sizeof(struct snapshot_inode_entry);
				continue;
			case SS_FILE_WRITE:
				nova_background_clean_write_entry(sb, addr,
							&fake_pi, trans_id);
				curr_p += sizeof(struct snapshot_file_write_entry);
				continue;
			default:
				nova_err(sb, "unknown type %d, 0x%llx, "
						"tail 0x%llx\n",
						type, curr_p, list->tail);
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
		if (ENTRY_LOC(curr_block)) {
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
	struct snapshot_list *list, int delete_entries)
{
	if (delete_entries)
		nova_delete_snapshot_list_entries(sb, list);
	nova_delete_snapshot_list_pages(sb, list);
	return 0;
}

static int nova_delete_snapshot_info(struct super_block *sb,
	struct snapshot_info *info, int delete_entries)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_list *list;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		list = &info->lists[i];
		mutex_lock(&list->list_mutex);
		nova_delete_snapshot_list(sb, list, delete_entries);
		mutex_unlock(&list->list_mutex);
	}

	kfree(info->lists);
	return 0;
}

static int nova_initialize_snapshot_info_pages(struct super_block *sb,
	struct snapshot_info *info, u64 trans_id)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_list *list;
	unsigned long new_page = 0;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		list = &info->lists[i];
		new_page = (unsigned long)kmalloc(PAGE_SIZE,
							GFP_KERNEL);
		/* Aligned to PAGE_SIZE */
		if (!new_page || ENTRY_LOC(new_page)) {
			nova_dbg("%s: failed\n", __func__);
			kfree((void *)new_page);
			return -ENOMEM;
		}

		nova_set_link_page_trans_id(sb, (void *)new_page, trans_id);
		nova_set_next_link_page_address(sb, (void *)new_page, 0);
		list->tail = list->head = new_page;
		list->num_pages = 1;
	}

	return 0;
}

static int nova_initialize_snapshot_info(struct super_block *sb,
	struct snapshot_info **ret_info, int init_pages, u64 trans_id)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_info *info;
	struct snapshot_list *list;
	int i;
	int ret;

	info = nova_alloc_snapshot_info(sb);
	if (!info)
		return -ENOMEM;

	info->lists = kzalloc(sbi->cpus * sizeof(struct snapshot_list),
							GFP_KERNEL);

	if (!info->lists) {
		nova_free_snapshot_info(info);
		goto fail;
	}

	for (i = 0; i < sbi->cpus; i++) {
		list = &info->lists[i];
		mutex_init(&list->list_mutex);
	}

	if (init_pages) {
		ret = nova_initialize_snapshot_info_pages(sb, info, trans_id);
		if (ret)
			goto fail;
	}

	*ret_info = info;
	return 0;

fail:
	for (i = 0; i < sbi->cpus; i++) {
		list = &info->lists[i];
		if (list->head)
			kfree((void *)list->head);
	}

	kfree(info->lists);
	nova_free_snapshot_info(info);

	*ret_info = NULL;
	return -ENOMEM;
}

static void nova_write_snapshot_list_entry(struct super_block *sb,
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

static int nova_append_snapshot_list_entry(struct super_block *sb,
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
			nova_set_link_page_trans_id(sb, (void *)new_page,
						info->trans_id);
			nova_set_next_link_page_address(sb,
						(void *)new_page, 0);
			goto retry;
		}
	}

	if (is_last_entry(curr_p, size)) {
		nova_set_entry_type((void *)curr_p, NEXT_PAGE);
		curr_p = next_list_page(curr_p);
	}

	nova_write_snapshot_list_entry(sb, list, curr_p, entry, size);
	mutex_unlock(&list->list_mutex);

	return 0;
}

/*
 * An entry is deleteable if
 * 1) It is created after the last snapshot, or
 * 2) It is created and deleted during the same snapshot period.
 */
static int nova_old_entry_deleteable(struct super_block *sb,
	u64 create_trans_id, u64 delete_trans_id,
	struct snapshot_info **ret_info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_info *info = NULL;
	int ret;

	if (create_trans_id >= delete_trans_id) {
		nova_dbg("%s: trans ID error: create %llu, "
				"delete %llu\n", __func__,
				create_trans_id,
				delete_trans_id);
		return -EINVAL;
	}

	if (create_trans_id > sbi->latest_snapshot_trans_id)
		return 1;

	ret = nova_find_target_snapshot_info(sb, create_trans_id, &info);
	if (ret < 0 || !info) {
		nova_dbg("%s: Snapshot info not found\n", __func__);
		return -EINVAL;
	}

	if (delete_trans_id <= info->trans_id)
		return 1;

	*ret_info = info;
	return 0;
}

static int nova_append_snapshot_file_write_entry(struct super_block *sb,
	struct snapshot_info *info, u64 nvmm, u64 num_pages,
	u64 delete_trans_id)
{
	struct snapshot_table *snapshot_table;
	struct snapshot_file_write_entry entry;
	int index;
	int ret;

	if (!info) {
		nova_dbg("%s: Snapshot info not found\n", __func__);
		return -EINVAL;
	}

	index = info->index;
	snapshot_table = nova_get_snapshot_table(sb);
	if (snapshot_table->entries[index].trans_id != info->trans_id) {
		nova_dbg("%s: Snapshot info unmatch, index %d, trans ID %llu, "
				"snapshot table trans ID %llu\n",
				__func__, index, info->trans_id,
				snapshot_table->entries[index].trans_id);
		return -EINVAL;
	}

	nova_dbgv("Append file write entry: block %llu, %llu pages, "
			"delete trans ID %llu to Snapshot %d, trans ID %llu\n",
			nvmm, num_pages, delete_trans_id,
			info->index, info->trans_id);

	memset(&entry, 0, sizeof(struct snapshot_file_write_entry));
	entry.type = SS_FILE_WRITE;
	entry.deleted = 0;
	entry.nvmm = nvmm;
	entry.num_pages = num_pages;
	entry.delete_trans_id = delete_trans_id;

	ret = nova_append_snapshot_list_entry(sb, info, &entry,
			sizeof(struct snapshot_file_write_entry));

	return ret;
}

int nova_append_data_to_snapshot(struct super_block *sb,
	struct nova_file_write_entry *entry, u64 nvmm, u64 num_pages,
	u64 delete_trans_id)
{
	struct snapshot_info *info = NULL;
	int ret;

	ret = nova_old_entry_deleteable(sb, entry->trans_id,
					delete_trans_id, &info);
	if (ret == 0)
		nova_append_snapshot_file_write_entry(sb, info, nvmm,
					num_pages, delete_trans_id);

	return ret;
}

static int nova_append_snapshot_inode_entry(struct super_block *sb,
	struct nova_inode *pi, struct snapshot_info *info)
{
	struct snapshot_table *snapshot_table;
	struct snapshot_inode_entry entry;
	int index;
	int ret;

	if (!info) {
		nova_dbg("%s: Snapshot info not found\n", __func__);
		return -EINVAL;
	}

	index = info->index;
	snapshot_table = nova_get_snapshot_table(sb);
	if (snapshot_table->entries[index].trans_id != info->trans_id) {
		nova_dbg("%s: Snapshot info unmatch, index %d, trans ID %llu, "
				"snapshot table trans ID %llu\n",
				__func__, index, info->trans_id,
				snapshot_table->entries[index].trans_id);
		return -EINVAL;
	}

	nova_dbgv("Append inode entry: inode %llu, delete trans ID %llu "
			"to Snapshot %d, trans ID %llu\n",
			pi->nova_ino, pi->delete_trans_id,
			info->index, info->trans_id);

	memset(&entry, 0, sizeof(struct snapshot_inode_entry));
	entry.type = SS_INODE;
	entry.deleted = 0;
	entry.nova_ino = pi->nova_ino;
	entry.delete_trans_id = pi->delete_trans_id;

	ret = nova_append_snapshot_list_entry(sb, info, &entry,
			sizeof(struct snapshot_inode_entry));

	return ret;
}

int nova_append_inode_to_snapshot(struct super_block *sb,
	struct nova_inode *pi)
{
	struct snapshot_info *info = NULL;
	int ret;

	ret = nova_old_entry_deleteable(sb, pi->create_trans_id,
					pi->delete_trans_id, &info);
	if (ret == 0)
		nova_append_snapshot_inode_entry(sb, pi, info);

	return ret;
}

int nova_encounter_mount_snapshot(struct super_block *sb, void *addr,
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
			if (pass_mount_snapshot(sb, attr_entry->trans_id))
				ret = 1;
			break;
		case LINK_CHANGE:
			linkc_entry = (struct nova_link_change_entry *)addr;
			if (pass_mount_snapshot(sb, linkc_entry->trans_id))
				ret = 1;
			break;
		case DIR_LOG:
			dentry = (struct nova_dentry *)addr;
			if (pass_mount_snapshot(sb, dentry->trans_id))
				ret = 1;
			break;
		case FILE_WRITE:
			fw_entry = (struct nova_file_write_entry *)addr;
			if (pass_mount_snapshot(sb, fw_entry->trans_id))
				ret = 1;
			break;
		default:
			break;
	}

	return ret;
}

static int nova_copy_snapshot_list_to_dram(struct super_block *sb,
	struct snapshot_list *list, struct snapshot_nvmm_list *nvmm_list)
{
	struct nova_inode_log_page *dram_page;
	void *curr_nvmm_addr;
	u64 curr_nvmm_block;
	u64 prev_dram_addr;
	u64 curr_dram_addr;
	unsigned long i;
	int ret;

	curr_dram_addr = list->head;
	prev_dram_addr = list->head;
	curr_nvmm_block = nvmm_list->head;
	curr_nvmm_addr = nova_get_block(sb, curr_nvmm_block);

	for (i = 0; i < nvmm_list->num_pages; i++) {
		/* Leave next_page field alone */
		ret = memcpy_mcsafe((void *)curr_dram_addr, curr_nvmm_addr,
						LAST_ENTRY);

		if (ret < 0) {
			nova_dbg("%s: Copy nvmm page %lu failed\n",
					__func__, i);
			continue;
		}

		dram_page = (struct nova_inode_log_page *)curr_dram_addr;
		prev_dram_addr = curr_dram_addr;
		curr_nvmm_block = next_log_page(sb, curr_nvmm_block);
		if (curr_nvmm_block < 0)
			break;
		curr_nvmm_addr = nova_get_block(sb, curr_nvmm_block);
		curr_dram_addr = dram_page->page_tail.next_page;
	}

	list->num_pages = nvmm_list->num_pages;
	list->tail = prev_dram_addr + ENTRY_LOC(nvmm_list->tail);

	return 0;
}

static int nova_allocate_snapshot_list_pages(struct super_block *sb,
	struct snapshot_list *list, struct snapshot_nvmm_list *nvmm_list,
	u64 trans_id)
{
	unsigned long prev_page = 0;
	unsigned long new_page = 0;
	unsigned long i;

	for (i = 0; i < nvmm_list->num_pages; i++) {
		new_page = (unsigned long)kmalloc(PAGE_SIZE,
							GFP_KERNEL);

		if (!new_page) {
			nova_dbg("%s ERROR: fail to allocate list pages\n",
					__func__);
			goto fail;
		}

		nova_set_link_page_trans_id(sb, (void *)new_page, trans_id);
		nova_set_next_link_page_address(sb, (void *)new_page, 0);

		if (i == 0)
			list->head = new_page;

		if (prev_page)
			nova_set_next_link_page_address(sb, (void *)prev_page,
							new_page);
		prev_page = new_page;
	}

	return 0;

fail:
	nova_delete_snapshot_list_pages(sb, list);
	return -ENOMEM;
}

static int nova_restore_snapshot_info_lists(struct super_block *sb,
	struct snapshot_info *info, int index)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_nvmm_info_table *nvmm_info_table;
	struct snapshot_nvmm_page *nvmm_page;
	struct snapshot_nvmm_info *nvmm_info;
	struct snapshot_list *list;
	struct snapshot_nvmm_list *nvmm_list;
	int i;
	int ret;

	nvmm_info_table = nova_get_nvmm_info_table(sb);
	nvmm_info = &nvmm_info_table->infos[index];
	nvmm_page = (struct snapshot_nvmm_page *)nova_get_block(sb,
						nvmm_info->nvmm_page_addr);

	for (i = 0; i < sbi->cpus; i++) {
		list = &info->lists[i];
		nvmm_list = &nvmm_page->lists[i];
		if (!list || !nvmm_list) {
			nova_dbg("%s: list NULL? list %p, nvmm list %p\n",
					__func__, list, nvmm_list);
			continue;
		}

		ret = nova_allocate_snapshot_list_pages(sb, list,
						nvmm_list, info->trans_id);
		if (ret) {
			nova_dbg("%s failure\n", __func__);
			return ret;
		}
		nova_copy_snapshot_list_to_dram(sb, list, nvmm_list);
	}

	return 0;
}

static int nova_restore_snapshot_info(struct super_block *sb, int index,
	u64 trans_id, int just_init)
{
	struct snapshot_table *snapshot_table;
	struct snapshot_info *info = NULL;
	int ret = 0;

	snapshot_table = nova_get_snapshot_table(sb);

	nova_dbg("Restore snapshot %d, trans ID %llu\n", index, trans_id);

	/* Allocate list pages on demand later */
	ret = nova_initialize_snapshot_info(sb, &info, just_init, trans_id);
	if (ret) {
		nova_dbg("%s: initialize snapshot info failed %d\n",
				__func__, ret);
		goto fail;
	}

	info->index = index;
	info->trans_id = trans_id;

	if (just_init == 0) {
		ret = nova_restore_snapshot_info_lists(sb, info, index);
		if (ret)
			goto fail;
	}

	ret = nova_insert_snapshot_info(sb, info);
	return ret;

fail:
	nova_delete_snapshot_info(sb, info, 0);
	return ret;
}

int nova_mount_snapshot(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_table *snapshot_table;
	u64 mount_trans_id;
	int index;

	snapshot_table = nova_get_snapshot_table(sb);

	index = sbi->mount_snapshot_index;
	if (index < 0 || index >= SNAPSHOT_TABLE_SIZE) {
		nova_dbg("%s: Mount invalid snapshot %d\n",
				__func__, index);
		sbi->mount_snapshot = 0;
		return -EINVAL;
	}

	mount_trans_id = snapshot_table->entries[index].trans_id;
	if (mount_trans_id == 0) {
		nova_dbg("%s: Mount invalid snapshot %d\n",
				__func__, index);
		sbi->mount_snapshot = 0;
		return -EINVAL;
	}

	sbi->mount_snapshot_trans_id = mount_trans_id;
	nova_dbg("Mount snapshot %d\n", index);
	return 0;
}

static int nova_delete_nvmm_info(struct super_block *sb,
	struct snapshot_nvmm_info *nvmm_info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_nvmm_page *nvmm_page;
	struct snapshot_nvmm_list *nvmm_list;
	struct nova_inode fake_pi;
	unsigned long nvmm_blocknr;
	int i;

	if (nvmm_info->trans_id == 0 || nvmm_info->nvmm_page_addr == 0)
		return 0;

	fake_pi.nova_ino = NOVA_SNAPSHOT_INO;
	fake_pi.i_blk_type = 0;

	nvmm_page = (struct snapshot_nvmm_page *)nova_get_block(sb,
						nvmm_info->nvmm_page_addr);

	for (i = 0; i < sbi->cpus; i++) {
		nvmm_list = &nvmm_page->lists[i];
		fake_pi.log_head = nvmm_list->head;
		fake_pi.log_tail = nvmm_list->tail;
		fake_pi.alter_log_head = fake_pi.alter_log_tail = 0;
		nova_free_inode_log(sb, &fake_pi);
	}

	nvmm_blocknr = nova_get_blocknr(sb, nvmm_info->nvmm_page_addr, 0);
	nova_free_log_blocks(sb, &fake_pi, nvmm_blocknr, 1);
	return 0;
}

static int nova_clear_nvmm_info_table(struct super_block *sb,
	int just_init)
{
	struct snapshot_table *snapshot_table;
	struct snapshot_nvmm_info_table *nvmm_info_table;
	struct snapshot_nvmm_info *nvmm_info;
	u64 trans_id;
	int i;

	snapshot_table = nova_get_snapshot_table(sb);
	nvmm_info_table = nova_get_nvmm_info_table(sb);

	if (just_init)
		/* No need to free because we do not set the bitmap. */
		goto out;

	for (i = 0; i < SNAPSHOT_TABLE_SIZE; i++) {
		trans_id = snapshot_table->entries[i].trans_id;

		if (trans_id) {
			nvmm_info = &nvmm_info_table->infos[i];
			nova_delete_nvmm_info(sb, nvmm_info);
		}
	}

out:
	memset(nvmm_info_table, '0', PAGE_SIZE);
	nova_flush_buffer(nvmm_info_table, PAGE_SIZE, 1);
	return 0;
}

/* For power failure recovery, just initialize the infos */
int nova_restore_snapshot_table(struct super_block *sb, int just_init)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_table *snapshot_table;
	int i, count = 0;
	u64 trans_id;
	int ret;

	snapshot_table = nova_get_snapshot_table(sb);

	sbi->curr_snapshot = 0;
	sbi->latest_snapshot_trans_id = 0;

	for (i = 0; i < SNAPSHOT_TABLE_SIZE; i++) {
		trans_id = snapshot_table->entries[i].trans_id;

		if (trans_id) {
			sbi->curr_snapshot = i;
			ret = nova_restore_snapshot_info(sb, i, trans_id,
							just_init);
			if (ret) {
				nova_dbg("%s: Restore snapshot %d, "
						" trans ID %llu failed\n",
						__func__, i, trans_id);
				goto out;
			}
			count++;
		}

		if (trans_id > sbi->latest_snapshot_trans_id)
			sbi->latest_snapshot_trans_id = trans_id;
	}

	nova_dbg("Recovered %d snapshots, current snapshot index %d, "
			"latest transaction ID %llu\n",
			count, sbi->curr_snapshot,
			sbi->latest_snapshot_trans_id);

out:
	nova_clear_nvmm_info_table(sb, just_init);

	return ret;
}

static int get_unused_snapshot_index(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_table *snapshot_table;
	int index;
	int i;

	snapshot_table = nova_get_snapshot_table(sb);

	/* Take current snapshot as hint */
	index = sbi->curr_snapshot;
	for (i = 0; i < SNAPSHOT_TABLE_SIZE; i++) {
		if (snapshot_table->entries[index].trans_id == 0)
			return index;

		index = (index + 1) % SNAPSHOT_TABLE_SIZE;
	}

	return -EINVAL;
}

int nova_create_snapshot(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *super = nova_get_super(sb);
	struct snapshot_table *snapshot_table;
	struct snapshot_info *info = NULL;
	int index;
	u64 timestamp = 0;
	u64 trans_id;
	int ret;

	snapshot_table = nova_get_snapshot_table(sb);

	trans_id = atomic64_read(&super->s_trans_id);
	if (sbi->latest_snapshot_trans_id == trans_id) {
		/* Do not create new snapshot if no new transactions */
		return 0;
	}

	/*
	 * Mark the create_snapshot_trans_id before starting the snapshot
	 * creation. We will check this during in-place updates for metadata
	 * and data, to prevent overwriting logs that might belong to a
	 * snapshot that is being created.
	 */
	sbi->create_snapshot_trans_id = trans_id;

	timestamp = CURRENT_TIME_SEC.tv_sec;

	ret = nova_initialize_snapshot_info(sb, &info, 1, trans_id);
	if (ret) {
		nova_dbg("%s: initialize snapshot info failed %d\n",
				__func__, ret);
		// Reset the create_snapshot_trans_id
		sbi->create_snapshot_trans_id = 0;
		return ret;
	}

	mutex_lock(&sbi->s_lock);
	info->trans_id = trans_id;

	if (sbi->num_snapshots >= SNAPSHOT_TABLE_SIZE) {
		nova_dbg("%s: Snapshot table full\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	index = get_unused_snapshot_index(sb);
	if (index < 0) {
		ret = -EINVAL;
		goto out;
	}

	snapshot_table->entries[index].trans_id = trans_id;
	snapshot_table->entries[index].timestamp = timestamp;
	nova_flush_buffer(&snapshot_table->entries[index],
				CACHELINE_SIZE, 1);
	sbi->num_snapshots++;
	sbi->curr_snapshot = index;
	sbi->latest_snapshot_trans_id = trans_id;

	info->index = index;
	ret = nova_insert_snapshot_info(sb, info);

out:
	// Reset the create_snapshot_trans_id
	sbi->create_snapshot_trans_id = 0;
	mutex_unlock(&sbi->s_lock);

	return ret;
}

static void wakeup_snapshot_cleaner(struct nova_sb_info *sbi)
{
	if (!waitqueue_active(&sbi->snapshot_cleaner_wait))
		return;

	nova_dbg("Wakeup snapshot cleaner thread\n");
	wake_up_interruptible(&sbi->snapshot_cleaner_wait);
}

static int nova_link_to_next_snapshot(struct super_block *sb,
	struct snapshot_info *prev_info, struct snapshot_info *next_info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_list *prev_list, *next_list;
	struct nova_inode_log_page *curr_page;
	u64 curr_block, curr_p;
	int i;

	nova_dbg("Link deleted snapshot %d to next snapshot %d, "
			"prev trans ID %llu, next trans ID %llu\n",
			prev_info->index, next_info->index,
			prev_info->trans_id, next_info->trans_id);

	if (prev_info->trans_id >= next_info->trans_id)
		nova_dbg("Error: prev trans ID %llu higher than "
			"next trans ID %llu\n",
			prev_info->trans_id, next_info->trans_id);

	for (i = 0; i < sbi->cpus; i++) {
		prev_list = &prev_info->lists[i];
		next_list = &next_info->lists[i];

		mutex_lock(&prev_list->list_mutex);
		mutex_lock(&next_list->list_mutex);

		/* Set NEXT_PAGE flag for prev lists */
		curr_p = prev_list->tail;
		if (!goto_next_list_page(sb, curr_p))
			nova_set_entry_type((void *)curr_p, NEXT_PAGE);

		/* Link the prev lists to the head of next lists */
		curr_block = BLOCK_OFF(prev_list->tail);
		curr_page = (struct nova_inode_log_page *)curr_block;
		nova_set_next_link_page_address(sb, curr_page, next_list->head);

		next_list->head = prev_list->head;
		next_list->num_pages += prev_list->num_pages;

		mutex_unlock(&next_list->list_mutex);
		mutex_unlock(&prev_list->list_mutex);
	}

	sbi->curr_clean_snapshot_info = next_info;
	wakeup_snapshot_cleaner(sbi);

	return 0;
}

int nova_delete_snapshot(struct super_block *sb, int index)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_table *snapshot_table;
	struct snapshot_info *info = NULL;
	struct snapshot_info *prev = NULL, *next = NULL;
	struct rb_root *tree;
	u64 trans_id;
	int delete = 0;
	int ret;

	snapshot_table = nova_get_snapshot_table(sb);

	if (index < 0 || index >= SNAPSHOT_TABLE_SIZE) {
		nova_dbg("%s: Invalid snapshot number %d\n", __func__, index);
		return -EINVAL;
	}

	mutex_lock(&sbi->s_lock);
	trans_id = snapshot_table->entries[index].trans_id;
	nova_dbg("Delete snapshot %d, trans ID %llu\n", index, trans_id);

	ret = nova_find_target_snapshot_info(sb, trans_id, &info);
	if (ret != 1 || info->trans_id != trans_id) {
		nova_dbg("%s: Snapshot info not found\n", __func__);
		goto update_snapshot_table;
	}

	next = nova_find_adjacent_snapshot_info(sb, info, 1);

	if (next) {
		nova_link_to_next_snapshot(sb, info, next);
	} else {
		/* Delete the last snapshot. Find the previous one. */
		prev = nova_find_adjacent_snapshot_info(sb, info, 0);
		if (prev)
			sbi->latest_snapshot_trans_id = prev->trans_id;
		else
			sbi->latest_snapshot_trans_id = 0;

		delete = 1;
	}

	tree = &sbi->snapshot_info_tree;
	rb_erase(&info->node, tree);

update_snapshot_table:

	snapshot_table->entries[index].trans_id = 0;
	snapshot_table->entries[index].timestamp = 0;
	sbi->num_snapshots--;
	nova_flush_buffer(&snapshot_table->entries[index],
				CACHELINE_SIZE, 1);
	mutex_unlock(&sbi->s_lock);

	if (delete)
		nova_delete_snapshot_info(sb, info, 1);

	nova_free_snapshot_info(info);

	return 0;
}

static int nova_copy_snapshot_list_to_nvmm(struct super_block *sb,
	struct snapshot_list *list, struct snapshot_nvmm_list *nvmm_list,
	u64 new_block)
{
	struct nova_inode_log_page *dram_page;
	void *curr_nvmm_addr;
	u64 curr_nvmm_block;
	u64 prev_nvmm_block;
	u64 curr_dram_addr;
	unsigned long i;

	curr_dram_addr = list->head;
	prev_nvmm_block = new_block;
	curr_nvmm_block = new_block;
	curr_nvmm_addr = nova_get_block(sb, curr_nvmm_block);

	for (i = 0; i < list->num_pages; i++) {
		/* Leave next_page field alone */
		memcpy_to_pmem_nocache(curr_nvmm_addr, (void *)curr_dram_addr,
						LAST_ENTRY);

		dram_page = (struct nova_inode_log_page *)curr_dram_addr;
		prev_nvmm_block = curr_nvmm_block;
		curr_nvmm_block = next_log_page(sb, curr_nvmm_block);
		if (curr_nvmm_block < 0)
			break;
		curr_nvmm_addr = nova_get_block(sb, curr_nvmm_block);
		curr_dram_addr = dram_page->page_tail.next_page;
	}

	nvmm_list->num_pages = list->num_pages;
	nvmm_list->tail = prev_nvmm_block + ENTRY_LOC(list->tail);
	nvmm_list->head = new_block;

	nova_flush_buffer(nvmm_list, sizeof(struct snapshot_nvmm_list), 1);

	return 0;
}

static int nova_save_snapshot_info(struct super_block *sb,
	struct snapshot_info *info, struct snapshot_nvmm_info *nvmm_info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode fake_pi;
	struct snapshot_list *list;
	struct snapshot_nvmm_page *nvmm_page;
	struct snapshot_nvmm_list *nvmm_list;
	unsigned long num_pages;
	int i;
	u64 nvmm_page_addr;
	u64 new_block;
	int allocated;

	fake_pi.nova_ino = NOVA_SNAPSHOT_INO;
	fake_pi.i_blk_type = 0;

	/* Support up to 128 CPUs */
	allocated = nova_allocate_inode_log_pages(sb, &fake_pi, 1,
							&nvmm_page_addr);
	if (allocated != 1) {
		nova_dbg("Error allocating NVMM info page\n");
		return -ENOMEM;
	}

	nvmm_page = (struct snapshot_nvmm_page *)nova_get_block(sb,
							nvmm_page_addr);

	for (i = 0; i < sbi->cpus; i++) {
		list = &info->lists[i];
		num_pages = list->num_pages;
		allocated = nova_allocate_inode_log_pages(sb, &fake_pi,
					num_pages, &new_block);
		if (allocated != num_pages) {
			nova_dbg("Error saving snapshot list: %d\n", allocated);
			return -ENOMEM;
		}
		nvmm_list = &nvmm_page->lists[i];
		nova_copy_snapshot_list_to_nvmm(sb, list, nvmm_list, new_block);
	}

	nvmm_info->nvmm_page_addr = nvmm_page_addr;
	nvmm_info->trans_id = info->trans_id;
	nova_flush_buffer(nvmm_info, sizeof(struct snapshot_nvmm_info), 1);

	return 0;
}

int nova_print_snapshot_table(struct super_block *sb, struct seq_file *seq)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_table *snapshot_table;
	struct snapshot_info *info;
	struct rb_root *tree;
	struct rb_node *temp;
	struct tm tm;
	int index = 0, count = 0;
	u64 timestamp;
	unsigned long local_time;

	snapshot_table = nova_get_snapshot_table(sb);

	seq_printf(seq, "========== NOVA snapshot table ==========\n");
	seq_printf(seq, "Index\tTrans ID\t      Date\t    Time\n");

	tree = &sbi->snapshot_info_tree;

	/* Print in trans ID increasing order */
	temp = rb_first(tree);
	while (temp) {
		info = container_of(temp, struct snapshot_info, node);
		index = info->index;

		timestamp = snapshot_table->entries[index].timestamp;
		local_time = timestamp - sys_tz.tz_minuteswest * 60;
		time_to_tm(local_time, 0, &tm);
		seq_printf(seq, "%5d\t%8llu\t%4lu-%02d-%02d\t%02d:%02d:%02d\n",
					index, info->trans_id,
					tm.tm_year + 1900, tm.tm_mon + 1,
					tm.tm_mday,
					tm.tm_hour, tm.tm_min, tm.tm_sec);

		temp = rb_next(temp);
		count++;
	}

	seq_printf(seq, "=========== Total %d snapshots ===========\n", count);
	return 0;
}

/* Support up to 256 snapshots */
int nova_save_snapshots(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_table *snapshot_table;
	struct snapshot_nvmm_info_table *nvmm_info_table;
	struct rb_root *tree;
	struct snapshot_info *info;
	struct snapshot_nvmm_info *nvmm_info;
	struct rb_node *temp;

	snapshot_table = nova_get_snapshot_table(sb);

	if (sbi->snapshot_cleaner_thread)
		kthread_stop(sbi->snapshot_cleaner_thread);

	if (sbi->mount_snapshot)
		return 0;

	tree = &sbi->snapshot_info_tree;
	nvmm_info_table = nova_get_nvmm_info_table(sb);
	memset(nvmm_info_table, '0', PAGE_SIZE);

	/* Save in increasing order */
	temp = rb_first(tree);
	while (temp) {
		info = container_of(temp, struct snapshot_info, node);
		nvmm_info = &nvmm_info_table->infos[info->index];
		nova_save_snapshot_info(sb, info, nvmm_info);
		nova_delete_snapshot_info(sb, info, 0);

		temp = rb_next(temp);
		rb_erase(&info->node, tree);
		nova_free_snapshot_info(info);
	}

	return 0;
}

int nova_destroy_snapshot_infos(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_table *snapshot_table;
	struct rb_root *tree;
	struct snapshot_info *info;
	struct rb_node *temp;

	snapshot_table = nova_get_snapshot_table(sb);

	tree = &sbi->snapshot_info_tree;

	/* Save in increasing order */
	temp = rb_first(tree);
	while (temp) {
		info = container_of(temp, struct snapshot_info, node);
		nova_delete_snapshot_info(sb, info, 0);

		temp = rb_next(temp);
		rb_erase(&info->node, tree);
		nova_free_snapshot_info(info);
	}

	return 0;
}

static void snapshot_cleaner_try_sleeping(struct nova_sb_info *sbi)
{
	DEFINE_WAIT(wait);
	prepare_to_wait(&sbi->snapshot_cleaner_wait, &wait, TASK_INTERRUPTIBLE);
	schedule();
	finish_wait(&sbi->snapshot_cleaner_wait, &wait);
}

static int nova_clean_snapshot(struct nova_sb_info *sbi)
{
	struct super_block *sb = sbi->sb;
	struct snapshot_info *info;
	struct snapshot_list *list;
	int i;

	if (!sbi->curr_clean_snapshot_info)
		return 0;

	info = sbi->curr_clean_snapshot_info;

	for (i = 0; i < sbi->cpus; i++) {
		list = &info->lists[i];

		mutex_lock(&list->list_mutex);
		nova_background_clean_snapshot_list(sb, list,
							info->trans_id);
		mutex_unlock(&list->list_mutex);
	}

	sbi->curr_clean_snapshot_info = NULL;
	return 0;
}

static int nova_snapshot_cleaner(void *arg)
{
	struct nova_sb_info *sbi = arg;

	nova_dbg("Running snapshot cleaner thread\n");
	for (;;) {
		snapshot_cleaner_try_sleeping(sbi);

		if (kthread_should_stop())
			break;

		nova_clean_snapshot(sbi);
	}

	if (sbi->curr_clean_snapshot_info)
		nova_clean_snapshot(sbi);

	return 0;
}

static int nova_snapshot_cleaner_init(struct nova_sb_info *sbi)
{
	int ret = 0;

	init_waitqueue_head(&sbi->snapshot_cleaner_wait);

	sbi->snapshot_cleaner_thread = kthread_run(nova_snapshot_cleaner,
		sbi, "nova_snapshot_cleaner");
	if (IS_ERR(sbi->snapshot_cleaner_thread)) {
		nova_info("Failed to start NOVA snapshot cleaner thread\n");
		ret = -1;
	}
	nova_info("Start NOVA snapshot cleaner thread.\n");
	return ret;
}

int nova_snapshot_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;

	sbi->snapshot_info_tree = RB_ROOT;
	ret = nova_snapshot_cleaner_init(sbi);

	return ret;
}

u64 nova_get_latest_snapshot_trans_id(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	return sbi->latest_snapshot_trans_id;
}

u64 nova_get_create_snapshot_trans_id(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	return sbi->create_snapshot_trans_id;
}



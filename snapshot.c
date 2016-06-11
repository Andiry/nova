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
	sbi->curr_snapshot++;
	sbi->latest_snapshot_trans_id = trans_id;
	if (sbi->curr_snapshot >= SNAPSHOT_TABLE_SIZE)
		sbi->curr_snapshot -= SNAPSHOT_TABLE_SIZE;
	mutex_unlock(&sbi->s_lock);

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
	nova_flush_buffer(&snapshot_table->entries[index],
				CACHELINE_SIZE, 1);
	mutex_unlock(&sbi->s_lock);

	return 0;
}


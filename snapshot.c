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

int nova_restore_snapshot_table(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_table *snapshot_table;
	int i;
	u64 prev_timestamp;

	snapshot_table = nova_get_snapshot_table(sb);

	if (!snapshot_table)
		return -EINVAL;

	prev_timestamp = 0;
	for (i = 0; i < SNAPSHOT_TABLE_SIZE; i++) {
		/* Find first unused slot */
		if (snapshot_table->timestamp[i] == 0) {
			sbi->curr_snapshot = i;
			return 0;
		}

		if (snapshot_table->timestamp[i] < prev_timestamp) {
			sbi->curr_snapshot = i;
			return 0;
		}

		prev_timestamp = snapshot_table->timestamp[i];
		sbi->latest_snapshot_time = prev_timestamp;
	}

	nova_dbg("%s: failed\n", __func__);
	return -EINVAL;
}

int nova_print_snapshot_table(struct super_block *sb, struct seq_file *seq)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_table *snapshot_table;
	int i, curr, count = 0;
	u64 sec, nsec;

	snapshot_table = nova_get_snapshot_table(sb);

	if (!snapshot_table)
		return -EINVAL;

	seq_printf(seq, "========== NOVA snapshot table ==========\n");

	/*  Print in reverse order */
	curr = sbi->curr_snapshot - 1;
	if (curr < 0)
		curr += SNAPSHOT_TABLE_SIZE;

	for (i = 0; i < SNAPSHOT_TABLE_SIZE; i++) {
		if (snapshot_table->timestamp[curr]) {
			sec = snapshot_table->timestamp[curr] >> 32;
			nsec = snapshot_table->timestamp[curr] & 0xFFFFFFFF;
			seq_printf(seq, "%d %llu.%llu\n", curr, sec, nsec);
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
	struct snapshot_table *snapshot_table;
	u64 timestamp = 0;

	snapshot_table = nova_get_snapshot_table(sb);

	if (!snapshot_table)
		return -EINVAL;

	mutex_lock(&sbi->s_lock);
	timestamp = (CURRENT_TIME_SEC.tv_sec << 32) |
			(CURRENT_TIME_SEC.tv_nsec);
	snapshot_table->timestamp[sbi->curr_snapshot] = timestamp;
	nova_flush_buffer(&snapshot_table->timestamp[sbi->curr_snapshot],
				CACHELINE_SIZE, 1);
	sbi->curr_snapshot++;
	sbi->latest_snapshot_time = timestamp;
	if (sbi->curr_snapshot >= SNAPSHOT_TABLE_SIZE)
		sbi->curr_snapshot -= SNAPSHOT_TABLE_SIZE;
	mutex_unlock(&sbi->s_lock);

	return 0;
}

/* FIXME: 1) Snapshot hole 2) latest snapshot time update */
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
	snapshot_table->timestamp[index] = 0;
	nova_flush_buffer(&snapshot_table->timestamp[index],
				CACHELINE_SIZE, 1);
	mutex_unlock(&sbi->s_lock);

	return 0;
}


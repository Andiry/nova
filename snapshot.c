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
	}

	nova_dbg("%s: failed\n", __func__);
	return -EINVAL;
}

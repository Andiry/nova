/*
 * BRIEF DESCRIPTION
 *
 * Symlink operations
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

#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/version.h>
#include "nova.h"

int nova_block_symlink(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, u64 log_block,
	unsigned long name_blocknr, const char *symname, int len, u64 trans_id)
{
	struct nova_file_write_entry *entry;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	u64 block;
	u32 time;
	char *blockp;

	/* First copy name to name block */
	block = nova_get_block_off(sb, name_blocknr, NOVA_BLOCK_TYPE_4K);
	blockp = (char *)nova_get_block(sb, block);

	nova_memunlock_block(sb, blockp);
	memcpy_to_pmem_nocache(blockp, symname, len);
	blockp[len] = '\0';
	nova_memlock_block(sb, blockp);

	/* Apply a write entry to the start of log page */
	block = log_block;
	entry = (struct nova_file_write_entry *)nova_get_block(sb, block);

	entry->entry_type = FILE_WRITE;
	entry->trans_id = trans_id;
	entry->pgoff = 0;
	entry->num_pages = cpu_to_le32(1);
	entry->invalid_pages = 0;
	entry->block = cpu_to_le64(nova_get_block_off(sb, name_blocknr,
							NOVA_BLOCK_TYPE_4K));
	time = CURRENT_TIME_SEC.tv_sec;
	entry->mtime = cpu_to_le32(time);
	entry->size = cpu_to_le64(len + 1);
	nova_flush_buffer(entry, CACHELINE_SIZE, 0);

	sih->log_pages = 1;
	pi->log_head = block;
	nova_update_tail(pi, block + sizeof(struct nova_file_write_entry));

	return 0;
}

/* FIXME: Temporary workaround */
static int nova_readlink_copy(char __user *buffer, int buflen, const char *link)
{
	int len = PTR_ERR(link);
	if (IS_ERR(link))
		goto out;

	len = strlen(link);
	if (len > (unsigned) buflen)
		len = buflen;
	if (copy_to_user(buffer, link, len))
		len = -EFAULT;
out:
	return len;
}

static int nova_readlink(struct dentry *dentry, char __user *buffer, int buflen)
{
	struct nova_file_write_entry *entry;
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	char *blockp;

	entry = (struct nova_file_write_entry *)nova_get_block(sb,
							pi->log_head);
	blockp = (char *)nova_get_block(sb, BLOCK_OFF(entry->block));

	return nova_readlink_copy(buffer, buflen, blockp);
}

static const char *nova_get_link(struct dentry *dentry, struct inode *inode,
	struct delayed_call *done)
{
	struct nova_file_write_entry *entry;
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	char *blockp;

	entry = (struct nova_file_write_entry *)nova_get_block(sb,
							pi->log_head);
	blockp = (char *)nova_get_block(sb, BLOCK_OFF(entry->block));

	return blockp;
}

const struct inode_operations nova_symlink_inode_operations = {
	.readlink	= nova_readlink,
	.get_link	= nova_get_link,
	.setattr	= nova_notify_change,
};

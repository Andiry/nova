/*
 * BRIEF DESCRIPTION
 *
 * Log methods
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

#include "nova.h"
#include "journal.h"
#include "inode.h"
#include "log.h"

static int nova_execute_invalidate_reassign_logentry(struct super_block *sb,
	void *entry, enum nova_entry_type type, int reassign,
	unsigned int num_free)
{
	struct nova_file_write_entry *fw_entry;
	int invalid = 0;

	switch (type) {
	case FILE_WRITE:
		fw_entry = (struct nova_file_write_entry *)entry;
		if (reassign)
			fw_entry->reassigned = 1;
		if (num_free)
			fw_entry->invalid_pages += num_free;
		if (fw_entry->invalid_pages == fw_entry->num_pages)
			invalid = 1;
		break;
	case DIR_LOG:
		if (reassign) {
			((struct nova_dentry *)entry)->reassigned = 1;
		} else {
			((struct nova_dentry *)entry)->invalid = 1;
			invalid = 1;
		}
		break;
	case SET_ATTR:
		((struct nova_setattr_logentry *)entry)->invalid = 1;
		invalid = 1;
		break;
	case LINK_CHANGE:
		((struct nova_link_change_entry *)entry)->invalid = 1;
		invalid = 1;
		break;
	default:
		break;
	}

	if (invalid) {
		u64 addr = nova_get_addr_off(NOVA_SB(sb), entry);

		nova_inc_page_invalid_entries(sb, addr);
	}

	nova_persist_entry(entry);
	return 0;
}

static int nova_invalidate_reassign_logentry(struct super_block *sb,
	void *entry, enum nova_entry_type type, int reassign,
	unsigned int num_free)
{
	nova_execute_invalidate_reassign_logentry(sb, entry, type,
						reassign, num_free);
	return 0;
}

static int nova_invalidate_logentry(struct super_block *sb, void *entry,
	enum nova_entry_type type, unsigned int num_free)
{
	return nova_invalidate_reassign_logentry(sb, entry, type, 0, num_free);
}

static int nova_reassign_logentry(struct super_block *sb, void *entry,
	enum nova_entry_type type)
{
	return nova_invalidate_reassign_logentry(sb, entry, type, 1, 0);
}

static inline int nova_invalidate_write_entry(struct super_block *sb,
	struct nova_file_write_entry *entry, int reassign,
	unsigned int num_free)
{
	if (!entry)
		return 0;

	if (num_free == 0 && entry->reassigned == 1)
		return 0;

	return nova_invalidate_reassign_logentry(sb, entry, FILE_WRITE,
							reassign, num_free);
}

unsigned int nova_free_old_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry,
	unsigned long pgoff, unsigned int num_free,
	bool delete_dead, u64 epoch_id)
{
	unsigned long old_nvmm;
	timing_t free_time;

	if (!entry)
		return 0;

	NOVA_START_TIMING(free_old_t, free_time);

	old_nvmm = get_nvmm(sb, sih, entry, pgoff);

	if (!delete_dead)
		nova_invalidate_write_entry(sb, entry, 1, num_free);

	nova_dbgv("%s: pgoff %lu, free %u blocks\n",
				__func__, pgoff, num_free);
	nova_free_data_blocks(sb, sih, old_nvmm, num_free);

	sih->i_blocks -= num_free;

	NOVA_END_TIMING(free_old_t, free_time);
	return num_free;
}

struct nova_file_write_entry *nova_find_next_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, pgoff_t pgoff)
{
	struct nova_file_write_entry *entry;
	void **entryp = NULL;
	int nr_entries;

	rcu_read_lock();
repeat:
	entry = NULL;
	nr_entries = radix_tree_gang_lookup_slot(&sih->tree,
					&entryp, NULL, pgoff, 1);
	if (!entryp)
		goto out;

	entry = radix_tree_deref_slot(entryp);
	if (unlikely(!entry))
		goto out;

	if (radix_tree_exception(entry)) {
		if (radix_tree_deref_retry(entry))
			goto repeat;

		entry = NULL;
		goto out;
	}

	if (!get_write_entry(entry))
		goto repeat;

	if (unlikely(entry != *entryp)) {
		put_write_entry(entry);
		goto repeat;
	}

out:
	rcu_read_unlock();
	return entry;
}

static void nova_update_setattr_entry(struct inode *inode,
	struct nova_setattr_logentry *entry,
	struct nova_log_entry_info *entry_info)
{
	struct iattr *attr = entry_info->attr;
	unsigned int ia_valid = attr->ia_valid, attr_mask;

	/* These files are in the lowest byte */
	attr_mask = ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE |
			ATTR_ATIME | ATTR_MTIME | ATTR_CTIME;

	entry->entry_type	= SET_ATTR;
	entry->attr	= ia_valid & attr_mask;
	entry->mode	= cpu_to_le16(inode->i_mode);
	entry->uid	= cpu_to_le32(i_uid_read(inode));
	entry->gid	= cpu_to_le32(i_gid_read(inode));
	entry->atime	= cpu_to_le32(inode->i_atime.tv_sec);
	entry->ctime	= cpu_to_le32(inode->i_ctime.tv_sec);
	entry->mtime	= cpu_to_le32(inode->i_mtime.tv_sec);
	entry->epoch_id = cpu_to_le64(entry_info->epoch_id);
	entry->trans_id	= cpu_to_le64(entry_info->trans_id);
	entry->invalid	= 0;

	if (ia_valid & ATTR_SIZE)
		entry->size = cpu_to_le64(attr->ia_size);
	else
		entry->size = cpu_to_le64(inode->i_size);

	nova_persist_entry(entry);
}

static void nova_update_link_change_entry(struct inode *inode,
	struct nova_link_change_entry *entry,
	struct nova_log_entry_info *entry_info)
{
	struct nova_inode_info_header *sih = NOVA_IH(inode);

	entry->entry_type	= LINK_CHANGE;
	entry->epoch_id		= cpu_to_le64(entry_info->epoch_id);
	entry->trans_id		= cpu_to_le64(entry_info->trans_id);
	entry->invalid		= 0;
	entry->links		= cpu_to_le16(inode->i_nlink);
	entry->ctime		= cpu_to_le32(inode->i_ctime.tv_sec);
	entry->flags		= cpu_to_le32(sih->i_flags);
	entry->generation	= cpu_to_le32(inode->i_generation);

	nova_persist_entry(entry);
}

static int nova_update_write_entry(struct super_block *sb,
	struct nova_file_write_entry *entry,
	struct nova_log_entry_info *entry_info)
{
	entry->epoch_id = cpu_to_le64(entry_info->epoch_id);
	entry->trans_id = cpu_to_le64(entry_info->trans_id);
	entry->mtime = cpu_to_le32(entry_info->time);
	entry->size = cpu_to_le64(entry_info->file_size);
	nova_persist_entry(entry);
	return 0;
}

static int nova_update_old_dentry(struct super_block *sb,
	struct inode *dir, struct nova_dentry *dentry,
	struct nova_log_entry_info *entry_info)
{
	unsigned short links_count;
	int link_change = entry_info->link_change;
	u64 addr;

	dentry->epoch_id = entry_info->epoch_id;
	dentry->trans_id = entry_info->trans_id;
	/* Remove_dentry */
	dentry->ino = cpu_to_le64(0);
	dentry->invalid = 1;
	dentry->mtime = cpu_to_le32(dir->i_mtime.tv_sec);

	links_count = cpu_to_le16(dir->i_nlink);
	if (links_count == 0 && link_change == -1)
		links_count = 0;
	else
		links_count += link_change;
	dentry->links_count = cpu_to_le16(links_count);

	addr = nova_get_addr_off(NOVA_SB(sb), dentry);
	nova_inc_page_invalid_entries(sb, addr);

	nova_persist_entry(dentry);

	return 0;
}

static int nova_update_new_dentry(struct super_block *sb,
	struct inode *dir, struct nova_dentry *entry,
	struct nova_log_entry_info *entry_info)
{
	struct dentry *dentry = entry_info->data;
	unsigned short links_count;
	int link_change = entry_info->link_change;

	entry->entry_type = DIR_LOG;
	entry->epoch_id = entry_info->epoch_id;
	entry->trans_id = entry_info->trans_id;
	entry->ino = entry_info->ino;
	entry->name_len = dentry->d_name.len;
	memcpy_to_pmem_nocache(entry->name, dentry->d_name.name,
				dentry->d_name.len);
	entry->name[dentry->d_name.len] = '\0';
	entry->mtime = cpu_to_le32(dir->i_mtime.tv_sec);
	//entry->size = cpu_to_le64(dir->i_size);

	links_count = cpu_to_le16(dir->i_nlink);
	if (links_count == 0 && link_change == -1)
		links_count = 0;
	else
		links_count += link_change;
	entry->links_count = cpu_to_le16(links_count);

	/* Update actual de_len */
	entry->de_len = cpu_to_le16(entry_info->file_size);

	nova_persist_entry(entry);

	return 0;
}

static int nova_update_log_entry(struct super_block *sb, struct inode *inode,
	void *entry, struct nova_log_entry_info *entry_info)
{
	enum nova_entry_type type = entry_info->type;

	switch (type) {
	case FILE_WRITE:
		if (entry_info->inplace)
			nova_update_write_entry(sb, entry, entry_info);
		else
			memcpy_to_pmem_nocache(entry, entry_info->data,
				sizeof(struct nova_file_write_entry));
		break;
	case DIR_LOG:
		if (entry_info->inplace)
			nova_update_old_dentry(sb, inode, entry, entry_info);
		else
			nova_update_new_dentry(sb, inode, entry, entry_info);
		break;
	case SET_ATTR:
		nova_update_setattr_entry(inode, entry, entry_info);
		break;
	case LINK_CHANGE:
		nova_update_link_change_entry(inode, entry, entry_info);
		break;
	default:
		break;
	}

	return 0;
}

static int nova_append_log_entry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode,
	struct nova_inode_info_header *sih,
	struct nova_log_entry_info *entry_info)
{
	void *entry;
	enum nova_entry_type type = entry_info->type;
	struct nova_inode_update *update = entry_info->update;
	u64 tail;
	u64 curr_p;
	size_t size;
	int extended = 0;

	if (type == DIR_LOG)
		size = entry_info->file_size;
	else
		size = nova_get_log_entry_size(sb, type);

	tail = update->tail;

	curr_p = nova_get_append_head(sb, pi, sih, tail, size,
						MAIN_LOG, 0, &extended);
	if (curr_p == 0)
		return -ENOSPC;

	nova_dbgv("%s: inode %lu, type %d entry @ 0x%llx\n",
				__func__, sih->ino, type, curr_p);

	entry = nova_get_block(sb, curr_p);
	/* inode is already updated with attr */
	memset(entry, 0, size);
	nova_update_log_entry(sb, inode, entry, entry_info);
	nova_inc_page_num_entries(sb, curr_p);
	update->curr_entry = curr_p;
	update->tail = curr_p + size;

	entry_info->curr_p = curr_p;
	return 0;
}

/* Perform lite transaction to atomically in-place update log entry */
static int nova_inplace_update_log_entry(struct super_block *sb,
	struct inode *inode, void *entry,
	struct nova_log_entry_info *entry_info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	enum nova_entry_type type = entry_info->type;
	u64 journal_tail;
	size_t size;
	int cpu;
	timing_t update_time;

	NOVA_START_TIMING(update_entry_t, update_time);
	size = nova_get_log_entry_size(sb, type);

	cpu = nova_get_cpuid(sb);
	spin_lock(&sbi->journal_locks[cpu]);
	journal_tail = nova_create_logentry_transaction(sb, entry, type, cpu);
	nova_update_log_entry(sb, inode, entry, entry_info);

	PERSISTENT_BARRIER();

	nova_commit_lite_transaction(sb, journal_tail, cpu);
	spin_unlock(&sbi->journal_locks[cpu]);

	NOVA_END_TIMING(update_entry_t, update_time);
	return 0;
}

/* Returns new tail after append */
static int nova_append_setattr_entry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode, struct iattr *attr,
	struct nova_inode_update *update, u64 *last_setattr, u64 epoch_id)
{
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	struct nova_log_entry_info entry_info;
	timing_t append_time;
	int ret;

	NOVA_START_TIMING(append_setattr_t, append_time);
	entry_info.type = SET_ATTR;
	entry_info.attr = attr;
	entry_info.update = update;
	entry_info.epoch_id = epoch_id;
	entry_info.trans_id = sih->trans_id;

	ret = nova_append_log_entry(sb, pi, inode, sih, &entry_info);
	if (ret) {
		nova_err(sb, "%s failed\n", __func__);
		goto out;
	}

	*last_setattr = sih->last_setattr;
	sih->last_setattr = entry_info.curr_p;

out:
	NOVA_END_TIMING(append_setattr_t, append_time);
	return ret;
}

/* Invalidate old setattr entry */
static int nova_invalidate_setattr_entry(struct super_block *sb,
	u64 last_setattr)
{
	struct nova_setattr_logentry *old_entry;
	void *addr;
	int ret;

	addr = (void *)nova_get_block(sb, last_setattr);
	old_entry = (struct nova_setattr_logentry *)addr;

	/* Do not invalidate setsize entries */
	if (!old_entry_freeable(sb, old_entry->epoch_id) ||
			(old_entry->attr & ATTR_SIZE))
		return 0;

	ret = nova_invalidate_logentry(sb, old_entry, SET_ATTR, 0);

	return ret;
}

static int nova_can_inplace_update_setattr(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 epoch_id)
{
	u64 last_log = 0;
	struct nova_setattr_logentry *entry = NULL;

	last_log = sih->last_setattr;
	if (last_log) {
		entry = (struct nova_setattr_logentry *)nova_get_block(sb,
								last_log);
		/* Do not overwrite setsize entry */
		if (entry->attr & ATTR_SIZE)
			return 0;
		if (entry->epoch_id == epoch_id)
			return 1;
	}

	return 0;
}

static int nova_inplace_update_setattr_entry(struct super_block *sb,
	struct inode *inode, struct nova_inode_info_header *sih,
	struct iattr *attr, u64 epoch_id)
{
	struct nova_setattr_logentry *entry = NULL;
	struct nova_log_entry_info entry_info;
	u64 last_log = 0;

	nova_dbgv("%s : Modifying last log entry for inode %lu\n",
				__func__, inode->i_ino);
	last_log = sih->last_setattr;
	entry = (struct nova_setattr_logentry *)nova_get_block(sb,
							last_log);

	entry_info.type = SET_ATTR;
	entry_info.attr = attr;
	entry_info.epoch_id = epoch_id;
	entry_info.trans_id = sih->trans_id;

	return nova_inplace_update_log_entry(sb, inode, entry,
					&entry_info);
}

int nova_handle_setattr_operation(struct super_block *sb, struct inode *inode,
	struct nova_inode *pi, unsigned int ia_valid, struct iattr *attr,
	u64 epoch_id)
{
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	struct nova_inode_update update;
	u64 last_setattr = 0;
	int ret;

	if (ia_valid & ATTR_MODE)
		sih->i_mode = inode->i_mode;

	/*
	 * Let's try to do inplace update.
	 */
	if (!(ia_valid & ATTR_SIZE) &&
			nova_can_inplace_update_setattr(sb, sih, epoch_id)) {
		nova_inplace_update_setattr_entry(sb, inode, sih,
						attr, epoch_id);
	} else {
		/* We are holding inode lock so OK to append the log */
		nova_dbgv("%s : Appending last log entry for inode ino = %lu\n",
				__func__, inode->i_ino);
		update.tail = 0;
		ret = nova_append_setattr_entry(sb, pi, inode, attr, &update,
						&last_setattr, epoch_id);
		if (ret) {
			nova_dbg("%s: append setattr entry failure\n",
								__func__);
			return ret;
		}

		nova_update_inode(sb, inode, pi, &update);
	}

	/* Invalidate old setattr entry */
	if (last_setattr)
		nova_invalidate_setattr_entry(sb, last_setattr);

	return 0;
}

/* Invalidate old link change entry */
int nova_invalidate_link_change_entry(struct super_block *sb,
	u64 old_link_change)
{
	struct nova_link_change_entry *old_entry;
	void *addr;
	int ret;

	if (old_link_change == 0)
		return 0;

	addr = (void *)nova_get_block(sb, old_link_change);
	old_entry = (struct nova_link_change_entry *)addr;

	if (!old_entry_freeable(sb, old_entry->epoch_id))
		return 0;

	ret = nova_invalidate_logentry(sb, old_entry, LINK_CHANGE, 0);

	return ret;
}

static int nova_can_inplace_update_lcentry(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 epoch_id)
{
	u64 last_log = 0;
	struct nova_link_change_entry *entry = NULL;

	last_log = sih->last_link_change;
	if (last_log) {
		entry = (struct nova_link_change_entry *)nova_get_block(sb,
								last_log);
		if (entry->epoch_id == epoch_id)
			return 1;
	}

	return 0;
}

static int nova_inplace_update_lcentry(struct super_block *sb,
	struct inode *inode, struct nova_inode_info_header *sih,
	u64 epoch_id)
{
	struct nova_link_change_entry *entry = NULL;
	struct nova_log_entry_info entry_info;
	u64 last_log = 0;

	last_log = sih->last_link_change;
	entry = (struct nova_link_change_entry *)nova_get_block(sb,
							last_log);

	entry_info.type = LINK_CHANGE;
	entry_info.epoch_id = epoch_id;
	entry_info.trans_id = sih->trans_id;

	return nova_inplace_update_log_entry(sb, inode, entry,
					&entry_info);
}

/* Returns new tail after append */
int nova_append_link_change_entry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode,
	struct nova_inode_update *update, u64 *old_linkc, u64 epoch_id)
{
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	struct nova_log_entry_info entry_info;
	int ret = 0;
	timing_t append_time;

	NOVA_START_TIMING(append_link_change_t, append_time);

	if (nova_can_inplace_update_lcentry(sb, sih, epoch_id)) {
		nova_inplace_update_lcentry(sb, inode, sih, epoch_id);
		update->tail = sih->log_tail;

		*old_linkc = 0;
		sih->trans_id++;
		goto out;
	}

	entry_info.type = LINK_CHANGE;
	entry_info.update = update;
	entry_info.epoch_id = epoch_id;
	entry_info.trans_id = sih->trans_id;

	ret = nova_append_log_entry(sb, pi, inode, sih, &entry_info);
	if (ret) {
		nova_err(sb, "%s failed\n", __func__);
		goto out;
	}

	*old_linkc = sih->last_link_change;
	sih->last_link_change = entry_info.curr_p;
	sih->trans_id++;
out:
	NOVA_END_TIMING(append_link_change_t, append_time);
	return ret;
}

int nova_assign_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry,
	bool free)
{
	struct nova_file_write_entry *old_entry;
	struct nova_file_write_entry *start_old_entry = NULL;
	void **pentry;
	unsigned long start_pgoff = entry->pgoff;
	unsigned long start_old_pgoff = 0;
	unsigned int num = entry->num_pages;
	unsigned int num_free = 0;
	unsigned long curr_pgoff;
	int i;
	int ret = 0;
	timing_t assign_time;

	NOVA_START_TIMING(assign_t, assign_time);
	for (i = 0; i < num; i++) {
		curr_pgoff = start_pgoff + i;
repeat:
		pentry = radix_tree_lookup_slot(&sih->tree, curr_pgoff);
		if (pentry) {
			old_entry = radix_tree_deref_slot(pentry);
			if (radix_tree_exception(old_entry)) {
				if (radix_tree_deref_retry(old_entry))
					goto repeat;
				radix_tree_replace_slot(&sih->tree, pentry,
						entry);
				continue;
			}

			lock_write_entry(old_entry);
			radix_tree_replace_slot(&sih->tree, pentry, entry);
			unlock_write_entry(old_entry);

			if (old_entry != start_old_entry) {
				if (start_old_entry && free)
					nova_free_old_entry(sb, sih,
							start_old_entry,
							start_old_pgoff,
							num_free, false,
							entry->epoch_id);
				nova_invalidate_write_entry(sb,
						start_old_entry, 1, 0);

				start_old_entry = old_entry;
				start_old_pgoff = curr_pgoff;
				num_free = 1;
			} else {
				num_free++;
			}
		} else {
			ret = radix_tree_insert(&sih->tree, curr_pgoff, entry);
			if (ret) {
				nova_dbg("%s: ERROR %d\n", __func__, ret);
				goto out;
			}
		}
	}

	if (start_old_entry && free)
		nova_free_old_entry(sb, sih, start_old_entry,
					start_old_pgoff, num_free, false,
					entry->epoch_id);

	nova_invalidate_write_entry(sb, start_old_entry, 1, 0);

out:
	NOVA_END_TIMING(assign_t, assign_time);

	return ret;
}

int nova_inplace_update_write_entry(struct super_block *sb,
	struct inode *inode, struct nova_file_write_entry *entry,
	struct nova_log_entry_info *entry_info)
{
	return nova_inplace_update_log_entry(sb, inode, entry,
					entry_info);
}

/*
 * Append a nova_file_write_entry to the current nova_inode_log_page.
 * blocknr and start_blk are pgoff.
 * We cannot update pi->log_tail here because a transaction may contain
 * multiple entries.
 */
int nova_append_file_write_entry(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, struct nova_file_write_item *item,
	struct nova_inode_update *update)
{
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	struct nova_file_write_entry *data = &item->entry;
	struct nova_log_entry_info entry_info;
	timing_t append_time;
	int ret;

	NOVA_START_TIMING(append_file_entry_t, append_time);

	entry_info.type = FILE_WRITE;
	entry_info.update = update;
	entry_info.data = data;
	entry_info.epoch_id = data->epoch_id;
	entry_info.trans_id = data->trans_id;
	entry_info.inplace = 0;

	ret = nova_append_log_entry(sb, pi, inode, sih, &entry_info);
	if (ret)
		nova_err(sb, "%s failed\n", __func__);

	NOVA_END_TIMING(append_file_entry_t, append_time);
	return ret;
}

/* Create dentry and delete dentry must be invalidated together */
int nova_invalidate_dentries(struct super_block *sb,
	struct nova_inode_update *update)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_dentry *create_dentry;
	struct nova_dentry *delete_dentry;
	u64 create_curr, delete_curr;
	int ret;

	create_dentry = update->create_dentry;
	delete_dentry = update->delete_dentry;

	if (!create_dentry)
		return 0;

	nova_reassign_logentry(sb, create_dentry, DIR_LOG);

	if (!old_entry_freeable(sb, create_dentry->epoch_id))
		return 0;

	create_curr = nova_get_addr_off(sbi, create_dentry);
	delete_curr = nova_get_addr_off(sbi, delete_dentry);

	nova_invalidate_logentry(sb, create_dentry, DIR_LOG, 0);

	ret = nova_invalidate_logentry(sb, delete_dentry, DIR_LOG, 0);

	return ret;
}

int nova_inplace_update_dentry(struct super_block *sb,
	struct inode *dir, struct nova_dentry *dentry, int link_change,
	u64 epoch_id)
{
	struct nova_inode_info_header *sih = NOVA_IH(dir);
	struct nova_log_entry_info entry_info;

	entry_info.type = DIR_LOG;
	entry_info.link_change = link_change;
	entry_info.epoch_id = epoch_id;
	entry_info.trans_id = sih->trans_id;
	entry_info.inplace = 1;

	return nova_inplace_update_log_entry(sb, dir, dentry,
					&entry_info);
}

int nova_append_dentry(struct super_block *sb, struct nova_inode *pi,
	struct inode *dir, struct dentry *dentry, u64 ino,
	unsigned short de_len, struct nova_inode_update *update,
	int link_change, u64 epoch_id)
{
	struct nova_inode_info_header *sih = NOVA_IH(dir);
	struct nova_log_entry_info entry_info;
	timing_t append_time;
	int ret;

	NOVA_START_TIMING(append_dir_entry_t, append_time);

	entry_info.type = DIR_LOG;
	entry_info.update = update;
	entry_info.data = dentry;
	entry_info.ino = ino;
	entry_info.link_change = link_change;
	entry_info.file_size = de_len;
	entry_info.epoch_id = epoch_id;
	entry_info.trans_id = sih->trans_id;
	entry_info.inplace = 0;

	ret = nova_append_log_entry(sb, pi, dir, sih, &entry_info);
	if (ret)
		nova_err(sb, "%s failed\n", __func__);

	dir->i_blocks = sih->i_blocks;

	NOVA_END_TIMING(append_dir_entry_t, append_time);
	return ret;
}

/* Coalesce log pages to a singly linked list */
static int nova_coalesce_log_pages(struct super_block *sb,
	unsigned long prev_blocknr, unsigned long first_blocknr,
	unsigned long num_pages)
{
	unsigned long next_blocknr;
	u64 curr_block, next_page;
	struct nova_inode_log_page *curr_page;
	int i;

	if (prev_blocknr) {
		/* Link prev block and newly allocated head block */
		curr_block = nova_get_block_off(sb, prev_blocknr,
						NOVA_BLOCK_TYPE_4K);
		curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, curr_block);
		next_page = nova_get_block_off(sb, first_blocknr,
				NOVA_BLOCK_TYPE_4K);
		nova_set_next_page_address(sb, curr_page, next_page, 0);
	}

	next_blocknr = first_blocknr + 1;
	curr_block = nova_get_block_off(sb, first_blocknr,
						NOVA_BLOCK_TYPE_4K);
	curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, curr_block);
	for (i = 0; i < num_pages - 1; i++) {
		next_page = nova_get_block_off(sb, next_blocknr,
				NOVA_BLOCK_TYPE_4K);
		nova_set_page_num_entries(sb, curr_page, 0, 0);
		nova_set_page_invalid_entries(sb, curr_page, 0, 0);
		nova_set_next_page_address(sb, curr_page, next_page, 0);
		curr_page++;
		next_blocknr++;
	}

	/* Last page */
	nova_set_page_num_entries(sb, curr_page, 0, 0);
	nova_set_page_invalid_entries(sb, curr_page, 0, 0);
	nova_set_next_page_address(sb, curr_page, 0, 1);
	return 0;
}

/* Log block resides in NVMM */
int nova_allocate_inode_log_pages(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long num_pages,
	u64 *new_block, int cpuid, enum nova_alloc_direction from_tail)
{
	unsigned long new_inode_blocknr;
	unsigned long first_blocknr;
	unsigned long prev_blocknr;
	int allocated;
	int ret_pages = 0;

	allocated = nova_new_log_blocks(sb, sih, &new_inode_blocknr,
			num_pages, ALLOC_NO_INIT, cpuid, from_tail);

	if (allocated <= 0) {
		nova_err(sb, "ERROR: no inode log page available: %d %d\n",
			num_pages, allocated);
		return allocated;
	}
	ret_pages += allocated;
	num_pages -= allocated;
	nova_dbg_verbose("Pi %lu: Alloc %d log blocks @ 0x%lx\n",
			sih->ino, allocated, new_inode_blocknr);

	/* Coalesce the pages */
	nova_coalesce_log_pages(sb, 0, new_inode_blocknr, allocated);
	first_blocknr = new_inode_blocknr;
	prev_blocknr = new_inode_blocknr + allocated - 1;

	/* Allocate remaining pages */
	while (num_pages) {
		allocated = nova_new_log_blocks(sb, sih,
					&new_inode_blocknr, num_pages,
					ALLOC_NO_INIT, cpuid, from_tail);

		nova_dbg_verbose("Alloc %d log blocks @ 0x%lx\n",
					allocated, new_inode_blocknr);
		if (allocated <= 0) {
			nova_dbg("%s: no inode log page available: %lu %d\n",
				__func__, num_pages, allocated);
			/* Return whatever we have */
			break;
		}
		ret_pages += allocated;
		num_pages -= allocated;
		nova_coalesce_log_pages(sb, prev_blocknr, new_inode_blocknr,
						allocated);
		prev_blocknr = new_inode_blocknr + allocated - 1;
	}

	*new_block = nova_get_block_off(sb, first_blocknr,
						NOVA_BLOCK_TYPE_4K);

	return ret_pages;
}

static int nova_initialize_inode_log(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	int log_id)
{
	u64 new_block;
	int allocated;

	allocated = nova_allocate_inode_log_pages(sb, sih,
					1, &new_block, ANY_CPU,
					log_id == MAIN_LOG ? 0 : 1);
	if (allocated != 1) {
		nova_err(sb, "%s ERROR: no inode log page available\n",
					__func__);
		return -ENOSPC;
	}

	pi->log_tail = new_block;
	nova_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 0);
	pi->log_head = new_block;
	sih->log_head = sih->log_tail = new_block;
	sih->log_pages = 1;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	return 0;
}

/*
 * Extend the log.  If the log is less than EXTEND_THRESHOLD pages, double its
 * allocated size.  Otherwise, increase by EXTEND_THRESHOLD. Then, do GC.
 */
static u64 nova_extend_inode_log(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 curr_p)
{
	u64 new_block = 0;
	int allocated;
	unsigned long num_pages;
	int ret;

	nova_dbgv("%s: inode %lu, curr 0x%llx\n", __func__, sih->ino, curr_p);

	if (curr_p == 0) {
		ret = nova_initialize_inode_log(sb, pi, sih, MAIN_LOG);
		if (ret)
			return 0;

		return sih->log_head;
	}

	num_pages = sih->log_pages >= EXTEND_THRESHOLD ?
				EXTEND_THRESHOLD : sih->log_pages;

	allocated = nova_allocate_inode_log_pages(sb, sih,
					num_pages, &new_block, ANY_CPU, 0);
	nova_dbg_verbose("Link block %llu to block %llu\n",
					curr_p >> PAGE_SHIFT,
					new_block >> PAGE_SHIFT);
	if (allocated <= 0) {
		nova_err(sb, "%s ERROR: no inode log page available\n",
					__func__);
		nova_dbg("curr_p 0x%llx, %lu pages\n", curr_p,
					sih->log_pages);
		return 0;
	}

	/* Perform GC */
	nova_inode_log_fast_gc(sb, pi, sih, curr_p,
			       new_block, allocated, 0);

	return new_block;
}

/* For thorough GC, simply append one more page */
static u64 nova_append_one_log_page(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 curr_p)
{
	struct nova_inode_log_page *curr_page;
	u64 new_block;
	u64 curr_block;
	int allocated;

	allocated = nova_allocate_inode_log_pages(sb, sih, 1, &new_block,
							ANY_CPU, 0);
	if (allocated != 1) {
		nova_err(sb, "%s: ERROR: no inode log page available\n",
				__func__);
		return 0;
	}

	if (curr_p == 0) {
		curr_p = new_block;
	} else {
		/* Link prev block and newly allocated head block */
		curr_block = BLOCK_OFF(curr_p);
		curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, curr_block);
		nova_set_next_page_address(sb, curr_page, new_block, 1);
	}

	return curr_p;
}

/* Get the append location. Extent the log if needed. */
u64 nova_get_append_head(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 tail, size_t size, int log_id,
	int thorough_gc, int *extended)
{
	u64 curr_p;

	if (tail)
		curr_p = tail;
	else
		curr_p = sih->log_tail;

	if (curr_p == 0 || (is_last_entry(curr_p, size) &&
				next_log_page(sb, curr_p) == 0)) {
		if (is_last_entry(curr_p, size)) {
			nova_set_next_page_flag(sb, curr_p);
		}

		/* Alternate log should not go here */
		if (log_id != MAIN_LOG)
			return 0;

		if (thorough_gc == 0) {
			curr_p = nova_extend_inode_log(sb, pi, sih, curr_p);
		} else {
			curr_p = nova_append_one_log_page(sb, sih, curr_p);
			/* For thorough GC */
			*extended = 1;
		}

		if (curr_p == 0)
			return 0;
	}

	if (is_last_entry(curr_p, size)) {
		nova_set_next_page_flag(sb, curr_p);
		curr_p = next_log_page(sb, curr_p);
	}

	return curr_p;
}

int nova_free_contiguous_log_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 head)
{
	unsigned long blocknr, start_blocknr = 0;
	u64 curr_block = head;
	u8 btype = sih->i_blk_type;
	int num_free = 0;
	int freed = 0;

	while (curr_block > 0) {
		if (ENTRY_LOC(curr_block)) {
			nova_dbg("%s: ERROR: invalid block %llu\n",
					__func__, curr_block);
			break;
		}

		blocknr = nova_get_blocknr(sb, le64_to_cpu(curr_block),
				    btype);
		nova_dbg_verbose("%s: free page %llu\n", __func__, curr_block);
		curr_block = next_log_page(sb, curr_block);

		if (start_blocknr == 0) {
			start_blocknr = blocknr;
			num_free = 1;
		} else {
			if (blocknr == start_blocknr + num_free) {
				num_free++;
			} else {
				/* A new start */
				nova_free_log_blocks(sb, sih, start_blocknr,
							num_free);
				freed += num_free;
				start_blocknr = blocknr;
				num_free = 1;
			}
		}
	}
	if (start_blocknr) {
		nova_free_log_blocks(sb, sih, start_blocknr, num_free);
		freed += num_free;
	}

	return freed;
}

int nova_free_inode_log(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih)
{
	int freed = 0;
	timing_t free_time;

	if (sih->log_head == 0 || sih->log_tail == 0)
		return 0;

	NOVA_START_TIMING(free_inode_log_t, free_time);

	/* The inode is invalid now, no need to fence */
	if (pi) {
		pi->log_head = pi->log_tail = 0;
		nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);
	}

	freed = nova_free_contiguous_log_blocks(sb, sih, sih->log_head);

	NOVA_END_TIMING(free_inode_log_t, free_time);
	return 0;
}

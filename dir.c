/*
 * BRIEF DESCRIPTION
 *
 * File operations for directories.
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

#include <linux/fs.h>
#include <linux/pagemap.h>
#include "nova.h"

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

struct nova_dentry *nova_find_dentry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_dentry *direntry;
	unsigned long hash;

	hash = BKDRHash(name, name_len);
	direntry = radix_tree_lookup(&sih->tree, hash);

	return direntry;
}

static int nova_insert_dir_radix_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name,
	int namelen, struct nova_dentry *direntry)
{
	unsigned long hash;
	int ret;

	hash = BKDRHash(name, namelen);
	nova_dbgv("%s: insert %s hash %lu\n", __func__, name, hash);

	/* FIXME: hash collision ignored here */
	ret = radix_tree_insert(&sih->tree, hash, direntry);
	if (ret)
		nova_dbg("%s ERROR %d: %s\n", __func__, ret, name);

	return ret;
}

static int nova_check_dentry_match(struct super_block *sb,
	struct nova_dentry *dentry, const char *name, int namelen)
{
	if (dentry->name_len != namelen)
		return -EINVAL;

	return strncmp(dentry->name, name, namelen);
}

static int nova_remove_dir_radix_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name, int namelen,
	int replay, struct nova_dentry **create_dentry)
{
	struct nova_dentry *entry;
	unsigned long hash;

	hash = BKDRHash(name, namelen);
	entry = radix_tree_delete(&sih->tree, hash);

	if (replay == 0) {
		if (!entry) {
			nova_dbg("%s ERROR: %s, length %d, hash %lu\n",
					__func__, name, namelen, hash);
			return -EINVAL;
		}

		if (entry->ino == 0 || entry->invalid ||
		    nova_check_dentry_match(sb, entry, name, namelen)) {
			nova_dbg("%s dentry not match: %s, length %d, "
					"hash %lu\n", __func__, name,
					namelen, hash);
			nova_dbg("dentry: type %d, inode %llu, name %s, "
					"namelen %u, rec len %u\n",
					entry->entry_type,
					le64_to_cpu(entry->ino),
					entry->name, entry->name_len,
					le16_to_cpu(entry->de_len));
			return -EINVAL;
		}

		if (create_dentry)
			*create_dentry = entry;
	}

	return 0;
}

void nova_delete_dir_tree(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	struct nova_dentry *direntry;
	unsigned long pos = 0;
	struct nova_dentry *entries[FREE_BATCH];
	timing_t delete_time;
	int nr_entries;
	int i;
	void *ret;

	NOVA_START_TIMING(delete_dir_tree_t, delete_time);

	do {
		nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pos, FREE_BATCH);
		for (i = 0; i < nr_entries; i++) {
			direntry = entries[i];
			BUG_ON(!direntry);
			pos = BKDRHash(direntry->name, direntry->name_len);
			ret = radix_tree_delete(&sih->tree, pos);
			if (!ret || ret != direntry) {
				nova_err(sb, "dentry: type %d, inode %llu, "
					"name %s, namelen %u, rec len %u\n",
					direntry->entry_type,
					le64_to_cpu(direntry->ino),
					direntry->name, direntry->name_len,
					le16_to_cpu(direntry->de_len));
				if (!ret)
					nova_dbg("ret is NULL\n");
			}
		}
		pos++;
	} while (nr_entries == FREE_BATCH);

	NOVA_END_TIMING(delete_dir_tree_t, delete_time);
	return;
}

/* ========================= Entry operations ============================= */

static void nova_update_dentry(struct inode *dir, struct dentry *dentry,
	struct nova_dentry *entry, u64 ino, unsigned short de_len,
	int link_change, u64 trans_id)
{
	unsigned short links_count;

	memset(entry, 0, de_len);
	entry->entry_type = DIR_LOG;
	entry->trans_id = trans_id;
	entry->ino = cpu_to_le64(ino);
	entry->name_len = dentry->d_name.len;
	memcpy_to_pmem_nocache(entry->name, dentry->d_name.name,
				dentry->d_name.len);
	entry->name[dentry->d_name.len] = '\0';
	entry->reassigned = 0;
	entry->invalid = 0;
	entry->mtime = cpu_to_le32(dir->i_mtime.tv_sec);
	entry->size = cpu_to_le64(dir->i_size);

	links_count = cpu_to_le16(dir->i_nlink);
	if (links_count == 0 && link_change == -1)
		links_count = 0;
	else
		links_count += link_change;
	entry->links_count = cpu_to_le16(links_count);

	/* Update actual de_len */
	entry->de_len = cpu_to_le16(de_len);

	/* Update checksum */
	nova_update_entry_csum(entry);

	nova_dbg_verbose("dir entry: ino %llu, entry len %u, "
			"name len %u, reassigned %u, csum 0x%x\n",
			entry->ino, entry->de_len,
			entry->name_len, entry->reassigned, entry->csum);

	nova_flush_buffer(entry, de_len, 0);
}

/*
 * Append a nova_dentry to the current nova_inode_log_page.
 * Note unlike append_file_write_entry(), this method returns the tail pointer
 * after append.
 */
static int nova_append_dir_inode_entry(struct super_block *sb,
	struct nova_inode *pidir, struct inode *dir,
	u64 ino, struct dentry *dentry, unsigned short de_len,
	struct nova_inode_update *update,
	int link_change, u64 trans_id)
{
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_dentry *entry;
	u64 curr_p;
	size_t size = de_len;
	int extended = 0;
	timing_t append_time;

	NOVA_START_TIMING(append_dir_entry_t, append_time);

	curr_p = nova_get_append_head(sb, pidir, sih, update->tail, size,
						MAIN_LOG, &extended);
	if (curr_p == 0)
		return -ENOSPC;

	entry = (struct nova_dentry *)nova_get_block(sb, curr_p);

	nova_update_dentry(dir, dentry, entry, ino, de_len,
						link_change, trans_id);
	update->curr_entry = curr_p;
	update->tail = update->curr_entry + de_len;

	if (replica_log == 0)
		goto out;

	curr_p = nova_get_append_head(sb, pidir, sih, update->alter_tail,
						size, ALTER_LOG, &extended);
	if (curr_p == 0)
		return -ENOSPC;

	entry = (struct nova_dentry *)nova_get_block(sb, curr_p);

	nova_update_dentry(dir, dentry, entry, ino, de_len,
						link_change, trans_id);
	update->alter_entry = curr_p;

	update->alter_tail = update->alter_entry + de_len;

out:
	dir->i_blocks = sih->i_blocks;
	NOVA_END_TIMING(append_dir_entry_t, append_time);
	return 0;
}

static unsigned int nova_init_dentry(struct super_block *sb,
	struct nova_dentry *de_entry, u64 self_ino, u64 parent_ino,
	u64 trans_id)
{
	struct nova_dentry *start = de_entry;
	unsigned int length;
	unsigned short de_len;

	de_len = NOVA_DIR_LOG_REC_LEN(1);
	memset(de_entry, 0, de_len);
	de_entry->entry_type = DIR_LOG;
	de_entry->trans_id = trans_id;
	de_entry->ino = cpu_to_le64(self_ino);
	de_entry->name_len = 1;
	de_entry->de_len = cpu_to_le16(de_len);
	de_entry->mtime = CURRENT_TIME_SEC.tv_sec;
	de_entry->size = sb->s_blocksize;
	de_entry->links_count = 1;
	strncpy(de_entry->name, ".\0", 2);
	nova_update_entry_csum(de_entry);

	length = de_len;

	de_entry = (struct nova_dentry *)((char *)de_entry + length);
	de_len = NOVA_DIR_LOG_REC_LEN(2);
	memset(de_entry, 0, de_len);
	de_entry->entry_type = DIR_LOG;
	de_entry->trans_id = trans_id;
	de_entry->ino = cpu_to_le64(parent_ino);
	de_entry->name_len = 2;
	de_entry->de_len = cpu_to_le16(de_len);
	de_entry->mtime = CURRENT_TIME_SEC.tv_sec;
	de_entry->size = sb->s_blocksize;
	de_entry->links_count = 2;
	strncpy(de_entry->name, "..\0", 3);
	nova_update_entry_csum(de_entry);
	length += de_len;

	nova_flush_buffer(start, length, 0);
	return length;
}

/* Append . and .. entries */
int nova_append_dir_init_entries(struct super_block *sb,
	struct nova_inode *pi, u64 self_ino, u64 parent_ino, u64 trans_id)
{
	struct nova_inode *alter_pi;
	u64 alter_pi_addr = 0;
	int allocated;
	int ret;
	u64 new_block;
	unsigned int length;
	struct nova_dentry *de_entry;

	if (pi->log_head) {
		nova_dbg("%s: log head exists @ 0x%llx!\n",
				__func__, pi->log_head);
		return - EINVAL;
	}

	allocated = nova_allocate_inode_log_pages(sb, pi, 1, &new_block);
	if (allocated != 1) {
		nova_err(sb, "ERROR: no inode log page available\n");
		return - ENOMEM;
	}
	pi->log_tail = pi->log_head = new_block;

	de_entry = (struct nova_dentry *)nova_get_block(sb, new_block);

	length = nova_init_dentry(sb, de_entry, self_ino, parent_ino, trans_id);

	nova_update_tail(pi, new_block + length);

	if (replica_log == 0)
		goto update_alter_inode;

	allocated = nova_allocate_inode_log_pages(sb, pi, 1, &new_block);
	if (allocated != 1) {
		nova_err(sb, "ERROR: no inode log page available\n");
		return - ENOMEM;
	}
	pi->alter_log_tail = pi->alter_log_head = new_block;

	de_entry = (struct nova_dentry *)nova_get_block(sb, new_block);

	length = nova_init_dentry(sb, de_entry, self_ino, parent_ino, trans_id);

	nova_update_alter_tail(pi, new_block + length);
	nova_update_alter_pages(sb, pi, pi->log_head,
						pi->alter_log_head);

update_alter_inode:

	nova_update_inode_checksum(pi);
	nova_flush_buffer(pi, sizeof(struct nova_inode), 0);

	if (replica_inode == 0)
		return 0;

	/* Get alternate inode address */
	ret = nova_get_alter_inode_address(sb, self_ino, &alter_pi_addr);
	if (ret)
		return ret;

	alter_pi = (struct nova_inode *)nova_get_block(sb, alter_pi_addr);
	if (!alter_pi)
		return -EINVAL;

	memcpy_to_pmem_nocache(alter_pi, pi, sizeof(struct nova_inode));

	return 0;
}

/* adds a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 */
int nova_add_dentry(struct dentry *dentry, u64 ino, int inc_link,
	struct nova_inode_update *update, u64 trans_id)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *pidir;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct nova_dentry *direntry;
	unsigned short loglen;
	int ret;
	u64 curr_entry;
	timing_t add_dentry_time;

	nova_dbg_verbose("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	nova_dbg_verbose("%s: %s %d\n", __func__, name, namelen);
	NOVA_START_TIMING(add_dentry_t, add_dentry_time);
	if (namelen == 0)
		return -EINVAL;

	pidir = nova_get_inode(sb, dir);

	/*
	 * XXX shouldn't update any times until successful
	 * completion of syscall, but too many callers depend
	 * on this.
	 */
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;

	loglen = NOVA_DIR_LOG_REC_LEN(namelen);
	ret = nova_append_dir_inode_entry(sb, pidir, dir, ino,
				dentry,	loglen, update,
				inc_link, trans_id);

	if (ret) {
		nova_dbg("%s: append dir entry failure\n", __func__);
		return ret;
	}

	curr_entry = update->curr_entry;
	direntry = (struct nova_dentry *)nova_get_block(sb, curr_entry);
	sih->last_dentry = curr_entry;
	ret = nova_insert_dir_radix_tree(sb, sih, name, namelen, direntry);

	NOVA_END_TIMING(add_dentry_t, add_dentry_time);
	return ret;
}

static int nova_can_inplace_update_dentry(struct super_block *sb,
	struct nova_dentry *dentry)
{
	u64 latest_snapshot_trans_id;

	latest_snapshot_trans_id = nova_get_create_snapshot_trans_id(sb);

	if (latest_snapshot_trans_id == 0)
		latest_snapshot_trans_id = nova_get_latest_snapshot_trans_id(sb);

	if (dentry && dentry->trans_id > latest_snapshot_trans_id)
		return 1;

	return 0;
}

static void nova_inplace_update_dentry(struct super_block *sb,
	struct inode *dir, struct nova_dentry *dentry, int link_change,
	u64 trans_id)
{
	unsigned short links_count;

	dentry->trans_id = trans_id;
	/* Only used for remove_dentry */
	dentry->ino = cpu_to_le64(0);
	dentry->invalid = 1;
	dentry->mtime = cpu_to_le32(dir->i_mtime.tv_sec);

	links_count = cpu_to_le16(dir->i_nlink);
	if (links_count == 0 && link_change == -1)
		links_count = 0;
	else
		links_count += link_change;
	dentry->links_count = cpu_to_le16(links_count);

	/* Update checksum */
	nova_update_entry_csum(dentry);
	nova_update_alter_entry(sb, dentry);

	nova_dbg_verbose("dir entry: ino %llu, entry len %u, "
			"name len %u, reassigned %u, csum 0x%x\n",
			dentry->ino, dentry->de_len,
			dentry->name_len, dentry->reassigned, dentry->csum);

}

/* removes a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 */
int nova_remove_dentry(struct dentry *dentry, int dec_link,
	struct nova_inode_update *update, u64 trans_id)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *pidir;
	struct qstr *entry = &dentry->d_name;
	struct nova_dentry *old_dentry = NULL;
	unsigned short loglen;
	int ret;
	u64 curr_entry;
	timing_t remove_dentry_time;

	NOVA_START_TIMING(remove_dentry_t, remove_dentry_time);

	update->create_dentry = NULL;
	update->delete_dentry = NULL;

	if (!dentry->d_name.len) {
		ret = -EINVAL;
		goto out;
	}

	ret = nova_remove_dir_radix_tree(sb, sih, entry->name, entry->len, 0,
					&old_dentry);

	if (ret)
		goto out;

	pidir = nova_get_inode(sb, dir);

	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;

	if (nova_can_inplace_update_dentry(sb, old_dentry)) {
		nova_inplace_update_dentry(sb, dir, old_dentry,
						dec_link, trans_id);
		curr_entry = nova_get_addr_off(sbi, old_dentry);

		sih->last_dentry = curr_entry;
		/* Leave create/delete_dentry to NULL */
		/* Do not change tail/alter_tail if used as input */
		if (update->tail == 0) {
			update->tail = pidir->log_tail;
			update->alter_tail = pidir->alter_log_tail;
		}
		goto out;
	}

	loglen = NOVA_DIR_LOG_REC_LEN(entry->len);
	ret = nova_append_dir_inode_entry(sb, pidir, dir, 0,
				dentry, loglen, update,
				dec_link, trans_id);

	if (ret) {
		nova_dbg("%s: append dir entry failure\n", __func__);
		goto out;
	}

	update->create_dentry = old_dentry;
	curr_entry = update->curr_entry;
	update->delete_dentry = (struct nova_dentry *)nova_get_block(sb,
						curr_entry);
	sih->last_dentry = curr_entry;
out:
	NOVA_END_TIMING(remove_dentry_t, remove_dentry_time);
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

	create_dentry->reassigned = 1;
	nova_update_entry_csum(create_dentry);
	nova_update_alter_entry(sb, create_dentry);

	if (!old_entry_freeable(sb, create_dentry->trans_id))
		return 0;

	create_curr = nova_get_addr_off(sbi, create_dentry);
	delete_curr = nova_get_addr_off(sbi, delete_dentry);

	ret = nova_check_alter_entry(sb, create_curr);
	if (ret) {
		nova_dbg("%s: check create alter_entry returned %d\n",
					__func__, ret);
		return ret;
	}

	create_dentry->invalid = 1;
	nova_update_entry_csum(create_dentry);

	ret = nova_check_alter_entry(sb, delete_curr);
	if (ret) {
		nova_dbg("%s: check delete alter_entry returned %d\n",
					__func__, ret);
		return ret;
	}

	delete_dentry->invalid = 1;
	nova_update_entry_csum(delete_dentry);

	nova_update_alter_entry(sb, create_dentry);
	nova_update_alter_entry(sb, delete_dentry);

	return 0;
}

inline int nova_replay_add_dentry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_dentry *entry)
{
	if (!entry->name_len)
		return -EINVAL;

	nova_dbg_verbose("%s: add %s\n", __func__, entry->name);
	return nova_insert_dir_radix_tree(sb, sih,
			entry->name, entry->name_len, entry);
}

inline int nova_replay_remove_dentry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_dentry *entry)
{
	nova_dbg_verbose("%s: remove %s\n", __func__, entry->name);
	nova_remove_dir_radix_tree(sb, sih, entry->name,
					entry->name_len, 1, NULL);
	return 0;
}

static inline void nova_rebuild_dir_time_and_size(struct super_block *sb,
	struct nova_inode *pi, struct nova_dentry *entry)
{
	if (!entry || !pi)
		return;

	pi->i_ctime = entry->mtime;
	pi->i_mtime = entry->mtime;
	pi->i_size = entry->size;
	pi->i_links_count = entry->links_count;
}

static void nova_reassign_last_dentry(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 curr_p)
{
	struct nova_dentry *dentry, *old_dentry;
	if (sih->last_dentry == 0) {
		sih->last_dentry = curr_p;
	} else {
		old_dentry = (struct nova_dentry *)nova_get_block(sb,
							sih->last_dentry);
		dentry = (struct nova_dentry *)nova_get_block(sb, curr_p);
		if (dentry->trans_id >= old_dentry->trans_id)
			sih->last_dentry = curr_p;
	}
}

int nova_rebuild_dir_inode_tree(struct super_block *sb,
	struct nova_inode *pi, u64 pi_addr,
	struct nova_inode_info_header *sih)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_dentry *entry = NULL;
	struct nova_setattr_logentry *attr_entry = NULL;
	struct nova_link_change_entry *lc_entry = NULL;
	struct nova_inode_log_page *curr_page;
	struct nova_inode *alter_pi;
	u64 ino = pi->nova_ino;
	unsigned short de_len;
	timing_t rebuild_time;
	void *addr;
	u64 curr_p;
	u64 curr_trans_id = 0;
	u64 next;
	u8 type;
	int ret;

	NOVA_START_TIMING(rebuild_dir_t, rebuild_time);
	nova_dbgv("Rebuild dir %llu tree\n", ino);

	sih->pi_addr = pi_addr;

	curr_p = pi->log_head;
	if (curr_p == 0) {
		nova_err(sb, "Dir %llu log is NULL!\n", ino);
		BUG();
	}

	nova_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
				curr_p, pi->log_tail);

	sih->log_pages = 1;
	while (curr_p != pi->log_tail) {
		if (goto_next_page(sb, curr_p)) {
			sih->log_pages++;
			curr_p = next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			nova_err(sb, "Dir %llu log is NULL!\n", ino);
			BUG();
		}

		addr = (void *)nova_get_block(sb, curr_p);
		if (!nova_verify_entry_csum(sb, addr)) {
			nova_err(sb, "%s: entry checksum fail "
				"inode %llu entry addr 0x%llx\n",
				__func__, ino, (u64)addr);
			break;
		}

		type = nova_get_entry_type(addr);

		if (sbi->mount_snapshot) {
			if (nova_encounter_mount_snapshot(sb, addr, type))
				break;
		}

		switch (type) {
			case SET_ATTR:
				attr_entry =
					(struct nova_setattr_logentry *)addr;
				nova_apply_setattr_entry(sb, pi, sih,
								attr_entry);
				sih->last_setattr = curr_p;
				curr_p += sizeof(struct nova_setattr_logentry);
				continue;
			case LINK_CHANGE:
				lc_entry =
					(struct nova_link_change_entry *)addr;
				if (lc_entry->trans_id >= curr_trans_id) {
					nova_apply_link_change_entry(sb, pi,
								lc_entry);
					curr_trans_id = lc_entry->trans_id;
				}
				sih->last_link_change = curr_p;
				curr_p += sizeof(struct nova_link_change_entry);
				continue;
			case DIR_LOG:
				break;
			default:
				nova_dbg("%s: unknown type %d, 0x%llx\n",
							__func__, type, curr_p);
				NOVA_ASSERT(0);
		}

		entry = (struct nova_dentry *)addr;
		nova_dbgv("curr_p: 0x%llx, type %d, ino %llu, "
			"name %s, namelen %u, csum 0x%x, rec len %u\n", curr_p,
			entry->entry_type, le64_to_cpu(entry->ino),
			entry->name, entry->name_len, entry->csum,
			le16_to_cpu(entry->de_len));

		nova_reassign_last_dentry(sb, sih, curr_p);

		if (entry->invalid == 0) {
			if (entry->ino > 0)
				ret = nova_replay_add_dentry(sb, sih, entry);
			else
				ret = nova_replay_remove_dentry(sb, sih, entry);
		}

		if (ret) {
			nova_err(sb, "%s ERROR %d\n", __func__, ret);
			break;
		}

		if (entry->trans_id >= curr_trans_id) {
			nova_rebuild_dir_time_and_size(sb, pi, entry);
			curr_trans_id = entry->trans_id;
		}

		de_len = le16_to_cpu(entry->de_len);
		curr_p += de_len;
	}

	sih->i_size = le64_to_cpu(pi->i_size);
	sih->i_mode = le64_to_cpu(pi->i_mode);

	nova_update_inode_checksum(pi);
	if (replica_inode) {
		alter_pi = (struct nova_inode *)nova_get_block(sb,
							sih->alter_pi_addr);
		memcpy_to_pmem_nocache(alter_pi, pi, sizeof(struct nova_inode));
	}

	/* Keep traversing until log ends */
	curr_p &= PAGE_MASK;
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr_p);
	while ((next = curr_page->page_tail.next_page) != 0) {
		sih->log_pages++;
		curr_p = next;
		curr_page = (struct nova_inode_log_page *)
			nova_get_block(sb, curr_p);
	}

	sih->i_blocks = sih->log_pages;

//	nova_print_dir_tree(sb, sih, ino);
	NOVA_END_TIMING(rebuild_dir_t, rebuild_time);
	return 0;
}

static int nova_readdir_slow(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pidir;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *child_pi;
	struct nova_dentry *entry;
	struct nova_dentry *entries[FREE_BATCH];
	int nr_entries;
	u64 pi_addr;
	unsigned long pos = 0;
	ino_t ino;
	int i;
	int ret;
	timing_t readdir_time;

	NOVA_START_TIMING(readdir_t, readdir_time);
	pidir = nova_get_inode(sb, inode);
	nova_dbgv("%s: ino %llu, size %llu, pos %llu\n",
			__func__, (u64)inode->i_ino,
			pidir->i_size, ctx->pos);

	if (!sih) {
		nova_dbg("%s: inode %lu sih does not exist!\n",
				__func__, inode->i_ino);
		ctx->pos = READDIR_END;
		return 0;
	}

	pos = ctx->pos;
	if (pos == READDIR_END)
		goto out;

	do {
		nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pos, FREE_BATCH);
		for (i = 0; i < nr_entries; i++) {
			entry = entries[i];
			pos = BKDRHash(entry->name, entry->name_len);
			ino = __le64_to_cpu(entry->ino);
			if (ino == 0)
				continue;

			ret = nova_get_inode_address(sb, ino, 0, &pi_addr, 0, 0);
			if (ret) {
				nova_dbg("%s: get child inode %lu address "
					"failed %d\n", __func__, ino, ret);
				ctx->pos = READDIR_END;
				return ret;
			}

			child_pi = nova_get_block(sb, pi_addr);
			nova_dbgv("ctx: ino %llu, name %s, "
				"name_len %u, de_len %u, csum 0x%x\n",
				(u64)ino, entry->name, entry->name_len,
				entry->de_len, entry->csum);
			if (!dir_emit(ctx, entry->name, entry->name_len,
				ino, IF2DT(le16_to_cpu(child_pi->i_mode)))) {
				nova_dbgv("Here: pos %llu\n", ctx->pos);
				return 0;
			}
			ctx->pos = pos + 1;
		}
		pos++;
	} while (nr_entries == FREE_BATCH);

out:
	NOVA_END_TIMING(readdir_t, readdir_time);
	return 0;
}

static u64 nova_find_next_dentry_addr(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 pos)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_file_write_entry *entry = NULL;
	struct nova_file_write_entry *entries[1];
	int nr_entries;
	u64 addr = 0;

	nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pos, 1);
	if (nr_entries == 1) {
		entry = entries[0];
		addr = nova_get_addr_off(sbi, entry);
	}

	return addr;
}

static int nova_readdir_fast(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pidir;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *child_pi;
	struct nova_inode *prev_child_pi = NULL;
	struct nova_dentry *entry = NULL;
	struct nova_dentry *prev_entry = NULL;
	unsigned short de_len;
	u64 pi_addr;
	unsigned long pos = 0;
	ino_t ino;
	void *addr;
	u64 curr_p;
	u8 type;
	int ret;
	timing_t readdir_time;

	NOVA_START_TIMING(readdir_t, readdir_time);
	pidir = nova_get_inode(sb, inode);
	nova_dbgv("%s: ino %llu, size %llu, pos 0x%llx\n",
			__func__, (u64)inode->i_ino,
			pidir->i_size, ctx->pos);

	if (pidir->log_head == 0) {
		nova_err(sb, "Dir %lu log is NULL!\n", inode->i_ino);
		BUG();
		return -EINVAL;
	}

	pos = ctx->pos;

	if (pos == 0) {
		curr_p = pidir->log_head;
	} else if (pos == READDIR_END) {
		goto out;
	} else {
		curr_p = nova_find_next_dentry_addr(sb, sih, pos);
		if (curr_p == 0)
			goto out;
	}

	while (curr_p != pidir->log_tail) {
		if (goto_next_page(sb, curr_p)) {
			curr_p = next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			nova_err(sb, "Dir %lu log is NULL!\n", inode->i_ino);
			BUG();
			return -EINVAL;
		}

		addr = (void *)nova_get_block(sb, curr_p);
		type = nova_get_entry_type(addr);
		switch (type) {
			case SET_ATTR:
				curr_p += sizeof(struct nova_setattr_logentry);
				continue;
			case LINK_CHANGE:
				curr_p += sizeof(struct nova_link_change_entry);
				continue;
			case DIR_LOG:
				break;
			default:
				nova_dbg("%s: unknown type %d, 0x%llx\n",
							__func__, type, curr_p);
			BUG();
			return -EINVAL;
		}

		entry = (struct nova_dentry *)nova_get_block(sb, curr_p);
		nova_dbgv("curr_p: 0x%llx, type %d, ino %llu, "
			"name %s, namelen %u, rec len %u\n", curr_p,
			entry->entry_type, le64_to_cpu(entry->ino),
			entry->name, entry->name_len,
			le16_to_cpu(entry->de_len));

		de_len = le16_to_cpu(entry->de_len);
		if (entry->ino > 0 && entry->invalid == 0
					&& entry->reassigned == 0) {
			ino = __le64_to_cpu(entry->ino);
			pos = BKDRHash(entry->name, entry->name_len);

			ret = nova_get_inode_address(sb, ino, 0, &pi_addr, 0, 0);
			if (ret) {
				nova_dbg("%s: get child inode %lu address "
					"failed %d\n", __func__, ino, ret);
				ctx->pos = READDIR_END;
				return ret;
			}

			child_pi = nova_get_block(sb, pi_addr);
			nova_dbgv("ctx: ino %llu, name %s, "
				"name_len %u, de_len %u\n",
				(u64)ino, entry->name, entry->name_len,
				entry->de_len);
			if (prev_entry && !dir_emit(ctx, prev_entry->name,
				prev_entry->name_len, ino,
				IF2DT(le16_to_cpu(prev_child_pi->i_mode)))) {
				nova_dbgv("Here: pos %llu\n", ctx->pos);
				return 0;
			}
			prev_entry = entry;
			prev_child_pi = child_pi;
		}
		ctx->pos = pos;
		curr_p += de_len;
	}

	if (prev_entry && !dir_emit(ctx, prev_entry->name,
			prev_entry->name_len, ino,
			IF2DT(le16_to_cpu(prev_child_pi->i_mode))))
		return 0;

	ctx->pos = READDIR_END;
out:
	NOVA_END_TIMING(readdir_t, readdir_time);
	nova_dbgv("%s return\n", __func__);
	return 0;
}

static int nova_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (sbi->mount_snapshot == 0)
		return nova_readdir_fast(file, ctx);
	else
		return nova_readdir_slow(file, ctx);
}

const struct file_operations nova_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= nova_readdir,
	.fsync		= noop_fsync,
	.unlocked_ioctl = nova_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= nova_compat_ioctl,
#endif
};

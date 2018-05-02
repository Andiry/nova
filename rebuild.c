/*
 * BRIEF DESCRIPTION
 *
 * Inode rebuild methods.
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
#include "inode.h"

/* entry given to this function is a copy in dram */
static void nova_apply_setattr_entry(struct super_block *sb,
	struct nova_inode_rebuild *reb,	struct nova_inode_info_header *sih,
	struct nova_setattr_logentry *entry)
{
	unsigned int data_bits = blk_type_to_shift[sih->i_blk_type];
	unsigned long first_blocknr, last_blocknr;
	loff_t start, end;
	int freed = 0;

	reb->i_mode	= entry->mode;
	reb->i_uid	= entry->uid;
	reb->i_gid	= entry->gid;
	reb->i_atime	= entry->atime;

	if (S_ISREG(reb->i_mode)) {
		start = entry->size;
		end = reb->i_size;

		first_blocknr = (start + (1UL << data_bits) - 1) >> data_bits;

		if (end > 0)
			last_blocknr = (end - 1) >> data_bits;
		else
			last_blocknr = 0;

		freed = nova_delete_file_tree(sb, sih, first_blocknr,
					last_blocknr, false, false, 0);
	}
}

/* entry given to this function is a copy in dram */
static void nova_apply_link_change_entry(struct super_block *sb,
	struct nova_inode_rebuild *reb,	struct nova_link_change_entry *entry)
{
	reb->i_links_count	= entry->links;
	reb->i_ctime		= entry->ctime;
	reb->i_flags		= entry->flags;
	reb->i_generation	= entry->generation;

	/* Do not flush now */
}

static void nova_update_inode_with_rebuild(struct super_block *sb,
	struct nova_inode_rebuild *reb, struct nova_inode *pi)
{
	pi->i_size = cpu_to_le64(reb->i_size);
	pi->i_flags = cpu_to_le32(reb->i_flags);
	pi->i_uid = cpu_to_le32(reb->i_uid);
	pi->i_gid = cpu_to_le32(reb->i_gid);
	pi->i_atime = cpu_to_le32(reb->i_atime);
	pi->i_ctime = cpu_to_le32(reb->i_ctime);
	pi->i_mtime = cpu_to_le32(reb->i_mtime);
	pi->i_generation = cpu_to_le32(reb->i_generation);
	pi->i_links_count = cpu_to_le16(reb->i_links_count);
	pi->i_mode = cpu_to_le16(reb->i_mode);
}

static int nova_init_inode_rebuild(struct super_block *sb,
	struct nova_inode_rebuild *reb, struct nova_inode *pi)
{
	struct nova_inode fake_pi;
	int rc;

	rc = memcpy_mcsafe(&fake_pi, pi, sizeof(struct nova_inode));
	if (rc)
		return rc;

	reb->i_size = le64_to_cpu(fake_pi.i_size);
	reb->i_flags = le32_to_cpu(fake_pi.i_flags);
	reb->i_uid = le32_to_cpu(fake_pi.i_uid);
	reb->i_gid = le32_to_cpu(fake_pi.i_gid);
	reb->i_atime = le32_to_cpu(fake_pi.i_atime);
	reb->i_ctime = le32_to_cpu(fake_pi.i_ctime);
	reb->i_mtime = le32_to_cpu(fake_pi.i_mtime);
	reb->i_generation = le32_to_cpu(fake_pi.i_generation);
	reb->i_links_count = le16_to_cpu(fake_pi.i_links_count);
	reb->i_mode = le16_to_cpu(fake_pi.i_mode);
	reb->trans_id = 0;

	return rc;
}

static inline void nova_rebuild_file_time_and_size(struct super_block *sb,
	struct nova_inode_rebuild *reb, u32 mtime, u32 ctime, u64 size)
{
	reb->i_mtime = cpu_to_le32(mtime);
	reb->i_ctime = cpu_to_le32(ctime);
	reb->i_size = cpu_to_le64(size);
}

static int nova_rebuild_inode_start(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	struct nova_inode_rebuild *reb, u64 pi_addr)
{
	int ret;

	ret = nova_get_head_tail(sb, pi, sih);
	if (ret)
		return ret;

	ret = nova_init_inode_rebuild(sb, reb, pi);
	if (ret)
		return ret;

	sih->pi_addr = pi_addr;

	nova_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
				sih->log_head, sih->log_tail);
	sih->log_pages = 1;

	return ret;
}

static int nova_rebuild_inode_finish(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	struct nova_inode_rebuild *reb, u64 curr_p)
{
	u64 next;

	sih->i_size = le64_to_cpu(reb->i_size);
	sih->i_mode = le64_to_cpu(reb->i_mode);
	sih->i_flags = le32_to_cpu(reb->i_flags);
	sih->trans_id = reb->trans_id + 1;

	nova_update_inode_with_rebuild(sb, reb, pi);
	nova_persist_inode(pi);

	/* Keep traversing until log ends */
	curr_p &= PAGE_MASK;
	while ((next = next_log_page(sb, curr_p)) > 0) {
		sih->log_pages++;
		curr_p = next;
	}

	return 0;
}

static void nova_rebuild_handle_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_inode_rebuild *reb,
	struct nova_file_write_entry *entry)
{
	if (entry->num_pages != entry->invalid_pages) {
		/*
		 * The overlaped blocks are already freed.
		 * Don't double free them, just re-assign the pointers.
		 */
		nova_assign_write_entry(sb, sih, entry, false);
	}

	if (entry->trans_id >= sih->trans_id) {
		nova_rebuild_file_time_and_size(sb, reb,
					entry->mtime, entry->mtime,
					entry->size);
		reb->trans_id = entry->trans_id;
	}

	/* Update sih->i_size for setattr apply operations */
	sih->i_size = le64_to_cpu(reb->i_size);
}

static int nova_rebuild_file_inode_tree(struct super_block *sb,
	struct nova_inode *pi, u64 pi_addr,
	struct nova_inode_info_header *sih)
{
	struct nova_file_write_entry *entry = NULL;
	struct nova_setattr_logentry *attr_entry = NULL;
	struct nova_link_change_entry *link_change_entry = NULL;
	struct nova_inode_rebuild rebuild, *reb;
	unsigned int data_bits = blk_type_to_shift[sih->i_blk_type];
	u64 ino = pi->nova_ino;
	timing_t rebuild_time;
	void *addr, *entryc = NULL;
	u64 curr_p;
	u8 type;
	int ret;

	NOVA_START_TIMING(rebuild_file_t, rebuild_time);
	nova_dbg_verbose("Rebuild file inode %llu tree\n", ino);

	reb = &rebuild;
	ret = nova_rebuild_inode_start(sb, pi, sih, reb, pi_addr);
	if (ret)
		goto out;

	curr_p = sih->log_head;
	if (curr_p == 0 && sih->log_tail == 0)
		goto out;

//	nova_print_nova_log(sb, sih);

	while (curr_p != sih->log_tail) {
		if (goto_next_page(sb, curr_p)) {
			sih->log_pages++;
			curr_p = next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			nova_err(sb, "File inode %llu log is NULL!\n", ino);
			ret = -EIO;
			goto out;
		}

		addr = (void *)nova_get_block(sb, curr_p);

		entryc = addr;

		type = nova_get_entry_type(entryc);

		switch (type) {
		case SET_ATTR:
			attr_entry = (struct nova_setattr_logentry *)entryc;
			nova_apply_setattr_entry(sb, reb, sih, attr_entry);
			sih->last_setattr = curr_p;
			if (attr_entry->trans_id >= reb->trans_id) {
				nova_rebuild_file_time_and_size(sb, reb,
							attr_entry->mtime,
							attr_entry->ctime,
							attr_entry->size);
				reb->trans_id = attr_entry->trans_id;
			}

			/* Update sih->i_size for setattr operation */
			sih->i_size = le64_to_cpu(reb->i_size);
			curr_p += sizeof(struct nova_setattr_logentry);
			break;
		case LINK_CHANGE:
			link_change_entry =
				(struct nova_link_change_entry *)entryc;
			nova_apply_link_change_entry(sb, reb,
						link_change_entry);
			sih->last_link_change = curr_p;
			curr_p += sizeof(struct nova_link_change_entry);
			break;
		case FILE_WRITE:
			entry = (struct nova_file_write_entry *)addr;
			nova_rebuild_handle_write_entry(sb, sih, reb,
						entryc);
			curr_p += sizeof(struct nova_file_write_entry);
			break;
		default:
			nova_err(sb, "unknown type %d, 0x%llx\n", type, curr_p);
			NOVA_ASSERT(0);
			nova_dbg("Inode %lu, log head 0x%llx, tail 0x%llx\n",
					sih->ino, sih->log_head, sih->log_tail);
			nova_print_curr_log_page(sb, curr_p);
			/* Discard unknown entries */
			sih->log_tail = curr_p;
			nova_update_tail(pi, curr_p);
			break;
		}

	}

	ret = nova_rebuild_inode_finish(sb, pi, sih, reb, curr_p);
	sih->i_blocks = sih->log_pages + (sih->i_size >> data_bits);

out:
//	nova_print_inode_log_page(sb, inode);
	NOVA_END_TIMING(rebuild_file_t, rebuild_time);
	return ret;
}

/******************* Directory rebuild *********************/

static inline void nova_rebuild_dir_time_and_size(struct super_block *sb,
	struct nova_inode_rebuild *reb, struct nova_dentry *entry)
{
	if (!entry || !reb)
		return;

	reb->i_ctime = entry->mtime;
	reb->i_mtime = entry->mtime;
	reb->i_links_count = entry->links_count;
	//reb->i_size = entry->size;
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

static inline int nova_replay_add_dentry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_dentry *entry)
{
	if (!entry->name_len)
		return -EINVAL;

	nova_dbg_verbose("%s: add %s\n", __func__, entry->name);
	return nova_insert_dir_tree(sb, sih,
			entry->name, entry->name_len, entry);
}

/* entry given to this function is a copy in dram */
static inline int nova_replay_remove_dentry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_dentry *entry)
{
	nova_dbg_verbose("%s: remove %s\n", __func__, entry->name);
	nova_remove_dir_tree(sb, sih, entry->name,
					entry->name_len, 1, NULL);
	return 0;
}

static int nova_rebuild_handle_dentry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_inode_rebuild *reb,
	struct nova_dentry *entry, u64 curr_p)
{
	int ret = 0;

	nova_dbgv("curr_p: 0x%llx, type %d, ino %llu, name %s, namelen %u, rec len %u\n",
			curr_p,
			entry->entry_type, le64_to_cpu(entry->ino),
			entry->name, entry->name_len,
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
		return ret;
	}

	if (entry->trans_id >= reb->trans_id) {
		nova_rebuild_dir_time_and_size(sb, reb, entry);
		reb->trans_id = entry->trans_id;
	}

	return ret;
}

int nova_rebuild_dir_inode_tree(struct super_block *sb,
	struct nova_inode *pi, u64 pi_addr,
	struct nova_inode_info_header *sih)
{
	struct nova_dentry *entry = NULL;
	struct nova_setattr_logentry *attr_entry = NULL;
	struct nova_link_change_entry *lc_entry = NULL;
	struct nova_inode_rebuild rebuild, *reb;
	u64 ino = pi->nova_ino;
	unsigned short de_len;
	timing_t rebuild_time;
	void *addr, *entryc = NULL;
	u64 curr_p;
	u8 type;
	int ret;

	NOVA_START_TIMING(rebuild_dir_t, rebuild_time);
	nova_dbgv("Rebuild dir %llu tree\n", ino);

	reb = &rebuild;
	ret = nova_rebuild_inode_start(sb, pi, sih, reb, pi_addr);
	if (ret)
		goto out;

	curr_p = sih->log_head;
	if (curr_p == 0) {
		nova_err(sb, "Dir %llu log is NULL!\n", ino);
		ret = -ENOSPC;
		goto out;
	}

	while (curr_p != sih->log_tail) {
		if (goto_next_page(sb, curr_p)) {
			sih->log_pages++;
			curr_p = next_log_page(sb, curr_p);
		}

		if (curr_p == 0) {
			nova_err(sb, "Dir %llu log is NULL!\n", ino);
			ret = -EIO;
			goto out;
		}

		addr = (void *)nova_get_block(sb, curr_p);

		entryc = addr;

		type = nova_get_entry_type(entryc);

		switch (type) {
		case SET_ATTR:
			attr_entry = (struct nova_setattr_logentry *)entryc;
			nova_apply_setattr_entry(sb, reb, sih, attr_entry);
			sih->last_setattr = curr_p;
			curr_p += sizeof(struct nova_setattr_logentry);
			break;
		case LINK_CHANGE:
			lc_entry = (struct nova_link_change_entry *)entryc;
			if (lc_entry->trans_id >= reb->trans_id) {
				nova_apply_link_change_entry(sb, reb, lc_entry);
				reb->trans_id = lc_entry->trans_id;
			}
			sih->last_link_change = curr_p;
			curr_p += sizeof(struct nova_link_change_entry);
			break;
		case DIR_LOG:
			entry = (struct nova_dentry *)addr;
			ret = nova_rebuild_handle_dentry(sb, sih, reb,
					entry, curr_p);
			if (ret)
				goto out;
			de_len = le16_to_cpu(DENTRY(entryc)->de_len);
			curr_p += de_len;
			break;
		default:
			nova_dbg("%s: unknown type %d, 0x%llx\n",
					__func__, type, curr_p);
			NOVA_ASSERT(0);
			nova_dbg("Inode %lu, log head 0x%llx, tail 0x%llx\n",
					sih->ino, sih->log_head, sih->log_tail);
			nova_print_curr_log_page(sb, curr_p);
			/* Discard unknown entries */
			sih->log_tail = curr_p;
			nova_update_tail(pi, curr_p);
			break;
		}
	}

	ret = nova_rebuild_inode_finish(sb, pi, sih, reb, curr_p);
	sih->i_blocks = sih->log_pages;

out:
	NOVA_END_TIMING(rebuild_dir_t, rebuild_time);
	return ret;
}

/* initialize nova inode header and other DRAM data structures */
int nova_rebuild_inode(struct super_block *sb, struct nova_inode_info *si,
	u64 ino, u64 pi_addr, int rebuild_dir)
{
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *pi;

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);
	// We need this valid in case we need to evict the inode.

	nova_init_header(sb, sih, __le16_to_cpu(pi->i_mode));
	sih->pi_addr = pi_addr;

	if (pi->deleted == 1) {
		nova_dbgv("%s: inode %llu has been deleted.\n", __func__, ino);
		return -ESTALE;
	}

	nova_dbgv("%s: inode %llu, addr 0x%llx, valid %d, head 0x%llx, tail 0x%llx\n",
			__func__, ino, pi_addr, pi->valid,
			pi->log_head, pi->log_tail);

	sih->ino = ino;

	switch (__le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFLNK:
		/* Treat symlink files as normal files */
		/* Fall through */
	case S_IFREG:
		nova_rebuild_file_inode_tree(sb, pi, pi_addr, sih);
		break;
	case S_IFDIR:
		if (rebuild_dir)
			nova_rebuild_dir_inode_tree(sb, pi, pi_addr, sih);
		break;
	default:
		/* In case of special inode, walk the log */
		if (pi->log_head)
			nova_rebuild_file_inode_tree(sb, pi, pi_addr, sih);
		sih->pi_addr = pi_addr;
		break;
	}

	return 0;
}


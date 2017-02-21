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

static int nova_execute_invalidate_reassign_logentry(struct super_block *sb,
	void *entry, enum nova_entry_type type, int reassign,
	unsigned int num_free)
{
	switch (type) {
		case FILE_WRITE:
			if (reassign)
				((struct nova_file_write_entry *)entry)->reassigned = 1;
			else
				((struct nova_file_write_entry *)entry)->invalid_pages
							+= num_free;
			break;
		case DIR_LOG:
			if (reassign)
				((struct nova_dentry *)entry)->reassigned = 1;
			else
				((struct nova_dentry *)entry)->invalid = 1;
			break;
		case SET_ATTR:
			((struct nova_setattr_logentry *)entry)->invalid = 1;
			break;
		case LINK_CHANGE:
			((struct nova_link_change_entry *)entry)->invalid = 1;
			break;
		case MMAP_WRITE:
			((struct nova_mmap_entry *)entry)->invalid = 1;
			break;
		default:
			break;
	}

	nova_update_entry_csum(entry);
	return 0;
}

static int nova_invalidate_reassign_logentry(struct super_block *sb,
	void *entry, enum nova_entry_type type, int reassign,
	unsigned int num_free)
{
	nova_memunlock_range(sb, entry, CACHELINE_SIZE);

	nova_execute_invalidate_reassign_logentry(sb, entry, type,
						reassign, num_free);
	nova_update_alter_entry(sb, entry);
	nova_memlock_range(sb, entry, CACHELINE_SIZE);

	return 0;
}

int nova_invalidate_logentry(struct super_block *sb, void *entry,
	enum nova_entry_type type, unsigned int num_free)
{
	return nova_invalidate_reassign_logentry(sb, entry, type, 0, num_free);
}

int nova_reassign_logentry(struct super_block *sb, void *entry,
	enum nova_entry_type type)
{
	return nova_invalidate_reassign_logentry(sb, entry, type, 1, 0);
}

static int nova_invalidate_file_write_entry(struct super_block *sb,
	struct nova_file_write_entry *entry, unsigned int num_free)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 curr;
	int ret;

	curr = nova_get_addr_off(sbi, entry);

	ret = nova_check_alter_entry(sb, curr);
	if (ret) {
		nova_dbg("%s: check_alter_entry returned %d\n", __func__, ret);
		return ret;
	}

	ret = nova_invalidate_logentry(sb, entry, FILE_WRITE, num_free);

	return ret;
}

static int nova_reassign_write_entry(struct super_block *sb,
	struct nova_file_write_entry *entry)
{
	if (!entry || entry->reassigned == 1)
		return 0;

	return nova_reassign_logentry(sb, entry, FILE_WRITE);
}

unsigned int nova_free_old_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry,
	unsigned long pgoff, unsigned int num_free,
	bool delete_dead, u64 trans_id)
{
	unsigned long old_nvmm;
	int ret;

	if (!entry)
		return 0;

	old_nvmm = get_nvmm(sb, sih, entry, pgoff);
	nova_reassign_write_entry(sb, entry);

	if (!delete_dead) {
		ret = nova_append_data_to_snapshot(sb, entry, old_nvmm,
				num_free, trans_id);
		if (ret == 0)
			goto out;
	}

	nova_invalidate_file_write_entry(sb, entry, num_free);

	nova_dbgv("%s: pgoff %lu, free %u blocks\n",
				__func__, pgoff, num_free);
	nova_free_data_blocks(sb, sih, old_nvmm, num_free);

out:
	sih->i_blocks -= num_free;

	return num_free;
}

struct nova_file_write_entry *nova_find_next_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, pgoff_t pgoff)
{
	struct nova_file_write_entry *entry = NULL;
	struct nova_file_write_entry *entries[1];
	int nr_entries;

	nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pgoff, 1);
	if (nr_entries == 1)
		entry = entries[0];

	return entry;
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
	int ret;
	timing_t assign_time;

	NOVA_START_TIMING(assign_t, assign_time);
	for (i = 0; i < num; i++) {
		curr_pgoff = start_pgoff + i;

		pentry = radix_tree_lookup_slot(&sih->tree, curr_pgoff);
		if (pentry) {
			old_entry = radix_tree_deref_slot(pentry);

			if (old_entry != start_old_entry) {
				if (start_old_entry && free)
					nova_free_old_entry(sb, sih,
							start_old_entry,
							start_old_pgoff,
							num_free, false,
							entry->trans_id);
				nova_reassign_write_entry(sb, start_old_entry);
				start_old_entry = old_entry;
				start_old_pgoff = curr_pgoff;
				num_free = 1;
			} else {
				num_free++;
			}

			radix_tree_replace_slot(&sih->tree, pentry, entry);
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
					entry->trans_id);

	nova_reassign_write_entry(sb, start_old_entry);

out:
	NOVA_END_TIMING(assign_t, assign_time);

	return ret;
}

/*
 * Zero the tail page. Used in resize request
 * to avoid to keep data in case the file grows again.
 */
void nova_clear_last_page_tail(struct super_block *sb,
	struct inode *inode, loff_t newsize)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned long offset = newsize & (sb->s_blocksize - 1);
	unsigned long pgoff, length;
	u64 nvmm;
	char *nvmm_addr;

	if (offset == 0 || newsize > inode->i_size)
		return;

	length = sb->s_blocksize - offset;
	pgoff = newsize >> sb->s_blocksize_bits;

	nvmm = nova_find_nvmm_block(sb, sih, NULL, pgoff);
	if (nvmm == 0)
		return;

	nvmm_addr = (char *)nova_get_block(sb, nvmm);
	nova_memunlock_range(sb, nvmm_addr + offset, length);
	memset(nvmm_addr + offset, 0, length);
	nova_flush_buffer(nvmm_addr + offset, length, 0);
	nova_memlock_range(sb, nvmm_addr + offset, length);

	/* Clear mmap page */
	if (sih->mmap_pages && pgoff <= sih->high_dirty &&
			pgoff >= sih->low_dirty) {
		nvmm = (unsigned long)radix_tree_lookup(&sih->cache_tree,
							pgoff);
		if (nvmm) {
			nvmm_addr = nova_get_block(sb, nvmm);
			nova_memunlock_range(sb, nvmm_addr + offset, length);
			memset(nvmm_addr + offset, 0, length);
			nova_memlock_range(sb, nvmm_addr + offset, length);
		}
	}
}

static void nova_update_setattr_entry(struct inode *inode,
	struct nova_setattr_logentry *entry, struct iattr *attr, u64 trans_id)
{
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
	entry->trans_id = trans_id;
	entry->invalid 	= 0;

	if (ia_valid & ATTR_SIZE)
		entry->size = cpu_to_le64(attr->ia_size);
	else
		entry->size = cpu_to_le64(inode->i_size);

	nova_update_entry_csum(entry);
	nova_flush_buffer(entry, sizeof(struct nova_setattr_logentry), 0);
}

/* Returns new tail after append */
static int nova_append_setattr_entry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode, struct iattr *attr,
	struct nova_inode_update *update, u64 *last_setattr, u64 trans_id)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_setattr_logentry *entry, *alter_entry;
	u64 tail, alter_tail;
	u64 curr_p, alter_curr_p;
	int extended = 0;
	size_t size = sizeof(struct nova_setattr_logentry);
	timing_t append_time;

	NOVA_START_TIMING(append_setattr_t, append_time);

	tail = update->tail;
	alter_tail = update->alter_tail;

	curr_p = nova_get_append_head(sb, pi, sih, tail, size,
						MAIN_LOG, 0, &extended);
	if (curr_p == 0)
		return -ENOSPC;

	nova_dbg_verbose("%s: inode %lu attr change entry @ 0x%llx\n",
				__func__, inode->i_ino, curr_p);

	entry = (struct nova_setattr_logentry *)nova_get_block(sb, curr_p);
	/* inode is already updated with attr */
	nova_memunlock_range(sb, entry, size);
	memset(entry, 0, size);
	nova_update_setattr_entry(inode, entry, attr, trans_id);
	nova_memlock_range(sb, entry, size);
	update->tail = curr_p + size;

	if (replica_metadata) {
		alter_curr_p = nova_get_append_head(sb, pi, sih, alter_tail,
						size, ALTER_LOG, 0, &extended);
		if (alter_curr_p == 0)
			return -ENOSPC;

		alter_entry = (struct nova_setattr_logentry *)nova_get_block(sb,
						alter_curr_p);
		nova_memunlock_range(sb, alter_entry, size);
		memset(alter_entry, 0, size);
		nova_update_setattr_entry(inode, alter_entry, attr, trans_id);
		nova_memlock_range(sb, alter_entry, size);

		update->alter_tail = alter_curr_p + size;
	}

	*last_setattr = sih->last_setattr;
	sih->last_setattr = curr_p;

	NOVA_END_TIMING(append_setattr_t, append_time);
	return 0;
}

/* Invalidate old link change entry */
static int nova_invalidate_setattr_entry(struct super_block *sb,
	struct inode *inode, u64 last_setattr)
{
	struct nova_setattr_logentry *old_entry;
	void *addr;
	int ret;

	addr = (void *)nova_get_block(sb, last_setattr);
	old_entry = (struct nova_setattr_logentry *)addr;
	/* Do not invalidate setsize entries */
	if (!old_entry_freeable(sb, old_entry->trans_id) ||
			(old_entry->attr & ATTR_SIZE))
		return 0;

	ret = nova_check_alter_entry(sb, last_setattr);
	if (ret) {
		nova_dbg("%s: check_alter_entry returned %d\n", __func__, ret);
		return ret;
	}

	ret = nova_invalidate_logentry(sb, old_entry, SET_ATTR, 0);

	return ret;
}

#if 0
static void setattr_copy_to_nova_inode(struct super_block *sb,
	struct inode *inode, struct nova_inode *pi, u64 trans_id)
{
	pi->i_mode  = cpu_to_le16(inode->i_mode);
	pi->i_uid	= cpu_to_le32(i_uid_read(inode));
	pi->i_gid	= cpu_to_le32(i_gid_read(inode));
	pi->i_atime	= cpu_to_le32(inode->i_atime.tv_sec);
	pi->i_ctime	= cpu_to_le32(inode->i_ctime.tv_sec);
	pi->i_mtime	= cpu_to_le32(inode->i_mtime.tv_sec);
	pi->create_trans_id = trans_id;

	nova_update_alter_inode(sb, inode, pi);
}
#endif

static int nova_can_inplace_update_setattr(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 latest_snapshot_trans_id)
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
		if (entry->trans_id > latest_snapshot_trans_id)
			return 1;
	}

	return 0;
}

static int nova_inplace_update_setattr_entry(struct super_block *sb,
	struct inode *inode, struct nova_inode_info_header *sih,
	struct iattr *attr, u64 trans_id)
{
	struct nova_setattr_logentry *entry = NULL;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	size_t size = sizeof(struct nova_setattr_logentry);
	u64 last_log = 0;
	int cpu;
	u64 journal_tail;

	nova_dbgv("%s : Modifying last log entry for inode %lu\n",
				__func__, inode->i_ino);
	last_log = sih->last_setattr;
	entry = (struct nova_setattr_logentry *)nova_get_block(sb,
							last_log);

	if (replica_metadata || unsafe_metadata) {
		nova_memunlock_range(sb, entry, size);
		nova_update_setattr_entry(inode, entry, attr, trans_id);
		// Also update the alter inode log entry.
		nova_update_alter_entry(sb, entry);
		nova_memlock_range(sb, entry, size);
		return 0;
	}

	cpu = smp_processor_id();
	spin_lock(&sbi->journal_locks[cpu]);
	nova_memunlock_journal(sb);
	journal_tail = nova_create_logentry_transaction(sb, entry,
						SET_ATTR, cpu);
	nova_update_setattr_entry(inode, entry, attr, trans_id);

	PERSISTENT_BARRIER();

	nova_commit_lite_transaction(sb, journal_tail, cpu);
	nova_memlock_journal(sb);
	spin_unlock(&sbi->journal_locks[cpu]);
	return 0;
}

int nova_handle_setattr_operation(struct super_block *sb, struct inode *inode,
	struct nova_inode *pi, unsigned int ia_valid, struct iattr *attr,
	u64 trans_id)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode_update update;
	u64 last_setattr = 0;
	u64 latest_snapshot_trans_id = 0;
	int ret;

	if (ia_valid & ATTR_MODE)
		sih->i_mode = inode->i_mode;

	/*
	 * Let's try to do inplace update.
	 * If there are currently no snapshots holding this inode,
	 * we can update the inode in place. If a snapshot creation
	 * is in progress, we will use the create_snapshot_trans_id
	 * as the latest snapshot id.
	*/
	latest_snapshot_trans_id = nova_get_create_snapshot_trans_id(sb);

	if (latest_snapshot_trans_id == 0)
		latest_snapshot_trans_id = nova_get_latest_snapshot_trans_id(sb);

	if (!(ia_valid & ATTR_SIZE) &&
			nova_can_inplace_update_setattr(sb, sih,
				latest_snapshot_trans_id)) {
		nova_inplace_update_setattr_entry(sb, inode, sih,
						attr, trans_id);
	} else {
		/* We are holding inode lock so OK to append the log */
		nova_dbgv("%s : Appending last log entry for inode ino = %lu\n",
				__func__, inode->i_ino);
		update.tail = update.alter_tail = 0;
		ret = nova_append_setattr_entry(sb, pi, inode, attr, &update,
				                &last_setattr, trans_id);
		if (ret) {
			nova_dbg("%s: append setattr entry failure\n", __func__);
			return ret;
		}

		nova_memunlock_inode(sb, pi);
		nova_update_inode(sb, inode, pi, &update, 1);
		nova_memlock_inode(sb, pi);
	}

	/* Invalidate old setattr entry */
	if (last_setattr)
		nova_invalidate_setattr_entry(sb, inode, last_setattr);

	return 0;
}

int nova_update_alter_pages(struct super_block *sb, struct nova_inode *pi,
	u64 curr, u64 alter_curr)
{
	if (curr == 0 || alter_curr == 0 || replica_metadata == 0)
		return 0;

	while (curr && alter_curr) {
		nova_set_alter_page_address(sb, curr, alter_curr);
		curr = next_log_page(sb, curr);
		alter_curr = next_log_page(sb, alter_curr);
	}

	if (curr || alter_curr)
		nova_dbg("%s: curr 0x%llx, alter_curr 0x%llx\n",
					__func__, curr, alter_curr);

	return 0;
}

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
		nova_memunlock_block(sb, curr_page);
		nova_set_next_page_address(sb, curr_page, next_page, 0);
		nova_memlock_block(sb, curr_page);
	}

	next_blocknr = first_blocknr + 1;
	curr_block = nova_get_block_off(sb, first_blocknr,
						NOVA_BLOCK_TYPE_4K);
	curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, curr_block);
	for (i = 0; i < num_pages - 1; i++) {
		next_page = nova_get_block_off(sb, next_blocknr,
				NOVA_BLOCK_TYPE_4K);
		nova_memunlock_block(sb, curr_page);
		nova_set_next_page_address(sb, curr_page, next_page, 0);
		nova_memlock_block(sb, curr_page);
		curr_page++;
		next_blocknr++;
	}

	/* Last page */
	nova_memunlock_block(sb, curr_page);
	nova_set_next_page_address(sb, curr_page, 0, 1);
	nova_memlock_block(sb, curr_page);
	return 0;
}

/* Log block resides in NVMM */
int nova_allocate_inode_log_pages(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long num_pages,
	u64 *new_block)
{
	unsigned long new_inode_blocknr;
	unsigned long first_blocknr;
	unsigned long prev_blocknr;
	int allocated;
	int ret_pages = 0;

	allocated = nova_new_log_blocks(sb, sih, &new_inode_blocknr,
					num_pages, 0);

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
					&new_inode_blocknr, num_pages, 0);

		nova_dbg_verbose("Alloc %d log blocks @ 0x%lx\n",
					allocated, new_inode_blocknr);
		if (allocated <= 0) {
			nova_dbg("%s: no inode log page available: "
				"%lu %d\n", __func__, num_pages, allocated);
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
					1, &new_block);
	if (allocated != 1) {
		nova_err(sb, "%s ERROR: no inode log page "
					"available\n", __func__);
		return -ENOSPC;
	}

	nova_memunlock_inode(sb, pi);
	if (log_id == MAIN_LOG) {
		pi->log_tail = new_block;
		nova_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 0);
		pi->log_head = new_block;
		sih->log_head = sih->log_tail = new_block;
		sih->log_pages = 1;
		sih->i_blocks++;
		nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);
	} else {
		pi->alter_log_tail = new_block;
		nova_flush_buffer(&pi->alter_log_tail, CACHELINE_SIZE, 0);
		pi->alter_log_head = new_block;
		sih->alter_log_head = sih->alter_log_tail = new_block;
		sih->log_pages++;
		sih->i_blocks++;
		nova_flush_buffer(&pi->alter_log_head, CACHELINE_SIZE, 1);
	}
	nova_memlock_inode(sb, pi);

	return 0;
}

static u64 nova_extend_inode_log(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 curr_p)
{
	u64 new_block, alter_new_block = 0;
	int allocated;
	unsigned long num_pages;
	int ret;

	nova_dbgv("%s: inode %lu, curr 0x%llx\n", __func__, sih->ino, curr_p);

	if (curr_p == 0) {
		ret = nova_initialize_inode_log(sb, pi, sih, MAIN_LOG);
		if (ret)
			return 0;

		if (replica_metadata) {
			ret = nova_initialize_inode_log(sb, pi, sih, ALTER_LOG);
			if (ret)
				return 0;

			nova_memunlock_inode(sb, pi);
			nova_update_alter_pages(sb, pi, sih->log_head,
							sih->alter_log_head);
			nova_memlock_inode(sb, pi);
		}

		return sih->log_head;
	}

	num_pages = sih->log_pages >= EXTEND_THRESHOLD ?
				EXTEND_THRESHOLD : sih->log_pages;
//	nova_dbg("Before append log pages:\n");
//	nova_print_inode_log_page(sb, inode);
	allocated = nova_allocate_inode_log_pages(sb, sih,
					num_pages, &new_block);
	nova_dbg_verbose("Link block %llu to block %llu\n",
					curr_p >> PAGE_SHIFT,
					new_block >> PAGE_SHIFT);
	if (allocated <= 0) {
		nova_err(sb, "%s ERROR: no inode log page "
					"available\n", __func__);
		nova_dbg("curr_p 0x%llx, %lu pages\n", curr_p,
					sih->log_pages);
		return 0;
	}

	if (replica_metadata) {
		allocated = nova_allocate_inode_log_pages(sb, sih,
					num_pages, &alter_new_block);
		if (allocated <= 0) {
			nova_err(sb, "%s ERROR: no inode log page "
					"available\n", __func__);
			nova_dbg("curr_p 0x%llx, %lu pages\n", curr_p,
					sih->log_pages);
			return 0;
		}

		nova_memunlock_inode(sb, pi);
		nova_update_alter_pages(sb, pi, new_block, alter_new_block);
		nova_memlock_inode(sb, pi);
	}


	nova_inode_log_fast_gc(sb, pi, sih, curr_p,
					new_block, alter_new_block, allocated);

//	nova_dbg("After append log pages:\n");
//	nova_print_inode_log_page(sb, inode);
	/* Atomic switch to new log */
//	nova_switch_to_new_log(sb, pi, new_block, num_pages);

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

	allocated = nova_allocate_inode_log_pages(sb, sih, 1, &new_block);
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
		nova_memunlock_block(sb, curr_page);
		nova_set_next_page_address(sb, curr_page, new_block, 1);
		nova_memlock_block(sb, curr_page);
	}

	return curr_p;
}

u64 nova_get_append_head(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 tail, size_t size, int log_id,
	int thorough_gc, int *extended)
{
	u64 curr_p;

	if (tail)
		curr_p = tail;
	else if (log_id == MAIN_LOG)
		curr_p = sih->log_tail;
	else
		curr_p = sih->alter_log_tail;

	if (curr_p == 0 || (is_last_entry(curr_p, size) &&
				next_log_page(sb, curr_p) == 0)) {
		if (is_last_entry(curr_p, size)) {
			nova_memunlock_block(sb, nova_get_block(sb, curr_p));
			nova_set_next_page_flag(sb, curr_p);
			nova_memlock_block(sb, nova_get_block(sb, curr_p));
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
		nova_memunlock_block(sb, nova_get_block(sb, curr_p));
		nova_set_next_page_flag(sb, curr_p);
		nova_memlock_block(sb, nova_get_block(sb, curr_p));
		curr_p = next_log_page(sb, curr_p);
	}

	return curr_p;
}

/*
 * Append a nova_file_write_entry to the current nova_inode_log_page.
 * blocknr and start_blk are pgoff.
 * We cannot update pi->log_tail here because a transaction may contain
 * multiple entries.
 */
int nova_append_file_write_entry(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, struct nova_file_write_entry *data,
	struct nova_inode_update *update)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry, *alter_entry;
	u64 tail, alter_tail;
	u64 curr_p, alter_curr_p;
	int extended = 0;
	size_t size = sizeof(struct nova_file_write_entry);
	timing_t append_time;

	NOVA_START_TIMING(append_file_entry_t, append_time);

	tail = update->tail;
	alter_tail = update->alter_tail;

	curr_p = nova_get_append_head(sb, pi, sih, tail, size,
						MAIN_LOG, 0, &extended);
	if (curr_p == 0)
		return -ENOSPC;

	entry = (struct nova_file_write_entry *)nova_get_block(sb, curr_p);
	nova_memunlock_range(sb, entry, size);
	nova_update_entry_csum(data);
	memcpy_to_pmem_nocache(entry, data,
			sizeof(struct nova_file_write_entry));
	nova_memlock_range(sb, entry, size);
	nova_dbg_verbose("file %lu entry @ 0x%llx: pgoff %llu, num %u, "
			"block %llu, size %llu, csum 0x%x\n", inode->i_ino,
			curr_p, entry->pgoff, entry->num_pages,
			entry->block >> PAGE_SHIFT, entry->size, entry->csum);
	/* entry->invalid is set to 0 */
	update->curr_entry = curr_p;
	update->tail = curr_p + size;

	if (replica_metadata) {
		alter_curr_p = nova_get_append_head(sb, pi, sih, alter_tail,
						size, ALTER_LOG, 0, &extended);
		if (alter_curr_p == 0)
			return -ENOSPC;

		alter_entry = (struct nova_file_write_entry *)nova_get_block(sb,
						alter_curr_p);
		nova_memunlock_range(sb, alter_entry, size);
		memcpy_to_pmem_nocache(alter_entry, data,
				sizeof(struct nova_file_write_entry));
		nova_memlock_range(sb, alter_entry, size);
		update->alter_entry = alter_curr_p;

		update->alter_tail = alter_curr_p + size;
	}

	NOVA_END_TIMING(append_file_entry_t, append_time);
	return 0;
}

int nova_free_inode_log(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih)
{
	int freed = 0;
	timing_t free_time;

	if (sih->log_head == 0 || sih->log_tail == 0)
		return 0;

	NOVA_START_TIMING(free_inode_log_t, free_time);

	/* The inode is invalid now, no need to call PCOMMIT */
	if (pi) {
		nova_memunlock_inode(sb, pi);
		pi->log_head = pi->log_tail = 0;
		pi->alter_log_head = pi->alter_log_tail = 0;
		nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);
		nova_memlock_inode(sb, pi);
	}

	freed = nova_free_contiguous_log_blocks(sb, sih, sih->log_head);
	if (replica_metadata)
		freed += nova_free_contiguous_log_blocks(sb, sih,
					sih->alter_log_head);

	NOVA_END_TIMING(free_inode_log_t, free_time);
	return 0;
}

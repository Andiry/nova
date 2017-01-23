/*
 * BRIEF DESCRIPTION
 *
 * DAX file operations.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/module.h>
#include <linux/buffer_head.h>
#include <asm/cpufeature.h>
#include <asm/pgtable.h>
#include <linux/version.h>
#include "nova.h"

int inplace_data_updates = 0;

module_param(inplace_data_updates, int, S_IRUGO);
MODULE_PARM_DESC(inplace_data_updates, "In-place Write Data Updates");

static ssize_t
do_dax_mapping_read(struct file *filp, char __user *buf,
	size_t len, loff_t *ppos)
{
	struct inode *inode = filp->f_mapping->host;
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;
	timing_t memcpy_time;

	pos = *ppos;
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	if (!access_ok(VERIFY_WRITE, buf, len)) {
		error = -EFAULT;
		goto out;
	}

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	nova_dbgv("%s: inode %lu, offset %lld, count %lu, size %lld\n",
		__func__, inode->i_ino,	pos, len, isize);

	if (len > isize - pos)
		len = isize - pos;

	if (len <= 0)
		goto out;

	end_index = (isize - 1) >> PAGE_SHIFT;
	do {
		unsigned long nr, left;
		unsigned long nvmm;
		unsigned long csum_blks;
		void *dax_mem = NULL;
		int zero = 0;

		/* nr is the maximum number of bytes to copy from this page */
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset) {
				goto out;
			}
		}

		entry = nova_get_write_entry(sb, si, index);
		if (unlikely(entry == NULL)) {
			nova_dbgv("Required extent not found: pgoff %lu, "
				"inode size %lld\n", index, isize);
			nr = PAGE_SIZE;
			zero = 1;
			goto memcpy;
		}

		/* Find contiguous blocks */
		if (index < entry->pgoff ||
			index - entry->pgoff >= entry->num_pages) {
			nova_err(sb, "%s ERROR: %lu, entry pgoff %llu, num %u, "
				"blocknr %llu\n", __func__, index, entry->pgoff,
				entry->num_pages, entry->block >> PAGE_SHIFT);
			return -EINVAL;
		}
		if (entry->reassigned == 0) {
			nr = (entry->num_pages - (index - entry->pgoff))
				* PAGE_SIZE;
		} else {
			nr = PAGE_SIZE;
		}

		nvmm = get_nvmm(sb, sih, entry, index);
		dax_mem = nova_get_block(sb, (nvmm << PAGE_SHIFT));

memcpy:
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		if ( (!zero) && (NOVA_SB(sb)->data_csum_base > 0) ) {
			/* only whole blocks can be verified */
			csum_blks = ((offset + nr - 1) >> PAGE_SHIFT) + 1;
			if (!nova_verify_data_csum(inode, entry,
						index, csum_blks)) {
				nova_err(sb, "%s: nova data checksum fail! "
					"inode %lu entry pgoff %lu "
					"index %lu blocks %lu\n", __func__,
					inode->i_ino, entry->pgoff,
					index, csum_blks);
				error = -EIO;
				goto out;
			}
		}

		NOVA_START_TIMING(memcpy_r_nvmm_t, memcpy_time);

		if (!zero)
			left = __copy_to_user(buf + copied,
						dax_mem + offset, nr);
		else
			left = __clear_user(buf + copied, nr);

		NOVA_END_TIMING(memcpy_r_nvmm_t, memcpy_time);

		if (left) {
			nova_dbg("%s ERROR!: bytes %lu, left %lu\n",
				__func__, nr, left);
			error = -EFAULT;
			goto out;
		}

		copied += (nr - left);
		offset += (nr - left);
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);

	NOVA_STATS_ADD(read_bytes, copied);

	nova_dbgv("%s returned %zu\n", __func__, copied);
	return (copied ? copied : error);
}

/*
 * Wrappers. We need to use the rcu read lock to avoid
 * concurrent truncate operation. No problem for write because we held
 * lock.
 */
ssize_t nova_dax_file_read(struct file *filp, char __user *buf,
			    size_t len, loff_t *ppos)
{
	ssize_t res;
	timing_t dax_read_time;

	NOVA_START_TIMING(dax_read_t, dax_read_time);
//	rcu_read_lock();
	res = do_dax_mapping_read(filp, buf, len, ppos);
//	rcu_read_unlock();
	NOVA_END_TIMING(dax_read_t, dax_read_time);
	return res;
}

static inline int nova_copy_partial_block(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry, unsigned long index,
	size_t offset, void* kmem, bool is_end_blk)
{
	void *ptr;
	unsigned long nvmm;

	nvmm = get_nvmm(sb, sih, entry, index);
	ptr = nova_get_block(sb, (nvmm << PAGE_SHIFT));
	if (ptr != NULL) {
		if (is_end_blk)
			memcpy(kmem + offset, ptr + offset,
				sb->s_blocksize - offset);
		else 
			memcpy(kmem, ptr, offset);
	}

	return 0;
}

/* 
 * Fill the new start/end block from original blocks.
 * Do nothing if fully covered; copy if original blocks present;
 * Fill zero otherwise.
 */
static void nova_handle_head_tail_blocks(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode, loff_t pos, size_t count,
	void *kmem)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	size_t offset, eblk_offset;
	unsigned long start_blk, end_blk, num_blocks;
	struct nova_file_write_entry *entry;
	timing_t partial_time;

	NOVA_START_TIMING(partial_block_t, partial_time);
	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	/* offset in the actual block size block */
	offset = pos & (nova_inode_blk_size(pi) - 1);
	start_blk = pos >> sb->s_blocksize_bits;
	end_blk = start_blk + num_blocks - 1;

	nova_dbg_verbose("%s: %lu blocks\n", __func__, num_blocks);
	/* We avoid zeroing the alloc'd range, which is going to be overwritten
	 * by this system call anyway */
	nova_dbg_verbose("%s: start offset %lu start blk %lu %p\n", __func__,
				offset, start_blk, kmem);
	if (offset != 0) {
		entry = nova_get_write_entry(sb, si, start_blk);
		if (entry == NULL) {
			/* Fill zero */
		    	memset(kmem, 0, offset);
		} else {
			/* Copy from original block */
			nova_copy_partial_block(sb, sih, entry, start_blk,
					offset, kmem, false);
		}
		nova_flush_buffer(kmem, offset, 0);
	}

	kmem = (void *)((char *)kmem +
			((num_blocks - 1) << sb->s_blocksize_bits));
	eblk_offset = (pos + count) & (nova_inode_blk_size(pi) - 1);
	nova_dbg_verbose("%s: end offset %lu, end blk %lu %p\n", __func__,
				eblk_offset, end_blk, kmem);
	if (eblk_offset != 0) {
		entry = nova_get_write_entry(sb, si, end_blk);
		if (entry == NULL) {
			/* Fill zero */
		    	memset(kmem + eblk_offset, 0,
					sb->s_blocksize - eblk_offset);
		} else {
			/* Copy from original block */
			nova_copy_partial_block(sb, sih, entry, end_blk,
					eblk_offset, kmem, true);
		}
		nova_flush_buffer(kmem + eblk_offset,
					sb->s_blocksize - eblk_offset, 0);
	}

	NOVA_END_TIMING(partial_block_t, partial_time);
}

int nova_reassign_file_tree(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	u64 begin_tail)
{
	struct nova_file_write_entry *entry_data;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct nova_file_write_entry);

	while (curr_p != sih->log_tail) {
		if (is_last_entry(curr_p, entry_size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_err(sb, "%s: File inode %llu log is NULL!\n",
				__func__, pi->nova_ino);
			return -EINVAL;
		}

		entry_data = (struct nova_file_write_entry *)
					nova_get_block(sb, curr_p);

		if (nova_get_entry_type(entry_data) != FILE_WRITE) {
			nova_dbg("%s: entry type is not write? %d\n",
				__func__, nova_get_entry_type(entry_data));
			curr_p += entry_size;
			continue;
		}

		nova_assign_write_entry(sb, pi, sih, entry_data, true);
		curr_p += entry_size;
	}

	return 0;
}

int nova_cleanup_incomplete_write(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	unsigned long blocknr, int allocated, u64 begin_tail, u64 end_tail)
{
	struct nova_file_write_entry *entry;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct nova_file_write_entry);

	if (blocknr > 0 && allocated > 0)
		nova_free_data_blocks(sb, pi, blocknr, allocated);

	if (begin_tail == 0 || end_tail == 0)
		return 0;

	while (curr_p != end_tail) {
		if (is_last_entry(curr_p, entry_size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_err(sb, "%s: File inode %llu log is NULL!\n",
				__func__, pi->nova_ino);
			return -EINVAL;
		}

		entry = (struct nova_file_write_entry *)
					nova_get_block(sb, curr_p);

		if (nova_get_entry_type(entry) != FILE_WRITE) {
			nova_dbg("%s: entry type is not write? %d\n",
				__func__, nova_get_entry_type(entry));
			curr_p += entry_size;
			continue;
		}

		blocknr = entry->block >> PAGE_SHIFT;
		nova_free_data_blocks(sb, pi, blocknr, entry->num_pages);
		curr_p += entry_size;
	}

	return 0;
}

void nova_init_file_write_entry(struct super_block *sb,
	struct nova_inode *pi, struct nova_file_write_entry *entry,
	u64 trans_id, u64 pgoff, int num_pages, u64 blocknr, u32 time, u64 size)
{
	memset(entry, 0, sizeof(struct nova_file_write_entry));
	entry->entry_type = FILE_WRITE;
	entry->reassigned = 0;
	entry->trans_id = trans_id;
	entry->pgoff = cpu_to_le64(pgoff);
	entry->num_pages = cpu_to_le32(num_pages);
	entry->invalid_pages = 0;
	entry->block = cpu_to_le64(nova_get_block_off(sb, blocknr,
							pi->i_blk_type));
	entry->mtime = cpu_to_le32(time);

	entry->size = size;
}

static ssize_t nova_cow_file_write(struct file *filp,
	const char __user *buf,	size_t len, loff_t *ppos, bool need_lock)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode    *inode = mapping->host;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi;
	struct nova_file_write_entry entry_data;
	struct nova_inode_update update;
	ssize_t     written = 0;
	loff_t pos;
	size_t count, offset, copied, csummed, ret;
	unsigned long start_blk, num_blocks;
	unsigned long total_blocks;
	unsigned long blocknr = 0;
	unsigned int data_bits;
	int allocated = 0;
	void* kmem;
	u64 entry_size;
	size_t bytes;
	long status = 0;
	timing_t cow_write_time, memcpy_time;
	unsigned long step = 0;
	u64 begin_tail = 0;
	u64 trans_id;
	u32 time;

	if (len == 0)
		return 0;

	/*
	 * We disallow writing to a mmaped file,
	 * since write is copy-on-write while mmap is DAX (in-place).
	 */
	if (mapping_mapped(mapping))
		return -EACCES;

	NOVA_START_TIMING(cow_write_t, cow_write_time);

	sb_start_write(inode->i_sb);
	if (need_lock)
		inode_lock(inode);

	if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	pos = *ppos;

	if (filp->f_flags & O_APPEND)
		pos = i_size_read(inode);

	count = len;

	pi = nova_get_inode(sb, inode);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;

	/* offset in the actual block size block */

	ret = file_remove_privs(filp);
	if (ret) {
		goto out;
	}
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	time = CURRENT_TIME_SEC.tv_sec;

	nova_dbgv("%s: inode %lu, offset %lld, count %lu\n",
			__func__, inode->i_ino,	pos, count);

	trans_id = nova_get_trans_id(sb);
	update.tail = sih->log_tail;
	update.alter_tail = sih->alter_log_tail;
	while (num_blocks > 0) {
		offset = pos & (nova_inode_blk_size(pi) - 1);
		start_blk = pos >> sb->s_blocksize_bits;

		/* don't zero-out the allocated blocks */
		allocated = nova_new_data_blocks(sb, pi, &blocknr, num_blocks,
						start_blk, 0, 1);
		nova_dbg_verbose("%s: alloc %d blocks @ %lu\n", __func__,
						allocated, blocknr);

		if (allocated <= 0) {
			nova_dbg("%s alloc blocks failed %d\n", __func__,
								allocated);
			ret = allocated;
			goto out;
		}

		step++;
		bytes = sb->s_blocksize * allocated - offset;
		if (bytes > count)
			bytes = count;

		kmem = nova_get_block(inode->i_sb,
			nova_get_block_off(sb, blocknr,	pi->i_blk_type));

		if (offset || ((offset + bytes) & (PAGE_SIZE - 1)) != 0)
			nova_handle_head_tail_blocks(sb, pi, inode, pos, bytes,
								kmem);

		/* Now copy from user buf */
//		nova_dbg("Write: %p\n", kmem);
		NOVA_START_TIMING(memcpy_w_nvmm_t, memcpy_time);
		copied = bytes - memcpy_to_pmem_nocache(kmem + offset,
						buf, bytes);
		NOVA_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

		if (pos + copied > inode->i_size)
			entry_size = cpu_to_le64(pos + copied);
		else
			entry_size = cpu_to_le64(inode->i_size);

		nova_init_file_write_entry(sb, pi, &entry_data, trans_id,
					start_blk, allocated, blocknr, time,
					entry_size);

		ret = nova_append_file_write_entry(sb, pi, inode,
					&entry_data, &update);
		if (ret) {
			nova_dbg("%s: append inode entry failed\n", __func__);
			ret = -ENOSPC;
			goto out;
		}

		if ( (copied > 0) && (NOVA_SB(sb)->data_csum_base > 0) ) {
			csummed = copied - nova_update_cow_csum(inode, blocknr,
						(void *) buf, offset, copied);
			if (unlikely(csummed != copied)) {
				nova_dbg("%s: not all data bytes are "
					"checksummed! copied %zu, "
					"csummed %zu\n", __func__,
					copied, csummed);
			}
		}

		nova_dbgv("Write: %p, %lu\n", kmem, copied);
		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			buf += copied;
			count -= copied;
			num_blocks -= allocated;
		}
		if (unlikely(copied != bytes)) {
			nova_dbg("%s ERROR!: %p, bytes %lu, copied %lu\n",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0)
			break;

		if (begin_tail == 0)
			begin_tail = update.curr_entry;
	}

	nova_memunlock_inode(sb, pi);
	data_bits = blk_type_to_shift[pi->i_blk_type];
	sih->i_blocks += (total_blocks << (data_bits - sb->s_blocksize_bits));
	nova_memlock_inode(sb, pi);

	nova_update_inode(sb, inode, pi, &update, 1);

	/* Free the overlap blocks after the write is committed */
	ret = nova_reassign_file_tree(sb, pi, sih, begin_tail);
	if (ret)
		goto out;

	inode->i_blocks = sih->i_blocks;

	ret = written;
	NOVA_STATS_ADD(cow_write_breaks, step);
	nova_dbgv("blocks: %lu, %lu\n", inode->i_blocks, sih->i_blocks);

	*ppos = pos;
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		sih->i_size = pos;
	}

out:
	if (ret < 0)
		nova_cleanup_incomplete_write(sb, pi, sih, blocknr, allocated,
						begin_tail, update.tail);

	if (need_lock)
		inode_unlock(inode);
	sb_end_write(inode->i_sb);
	NOVA_END_TIMING(cow_write_t, cow_write_time);
	NOVA_STATS_ADD(cow_write_bytes, written);
	return ret;
}

/*
 * Check if there is an existing entry for target page offset.
 * Used for inplace write, direct IO, DAX-mmap and fallocate.
 */
unsigned long nova_check_existing_entry(struct super_block *sb,
	struct inode *inode, unsigned long num_blocks, unsigned long start_blk,
	struct nova_file_write_entry **ret_entry, int check_next, int *inplace)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry;
	u64 latest_snapshot_trans_id;
	unsigned long next_pgoff;
	unsigned long ent_blks = 0;

	latest_snapshot_trans_id = nova_get_create_snapshot_trans_id(sb);

	if (latest_snapshot_trans_id == 0)
		latest_snapshot_trans_id = nova_get_latest_snapshot_trans_id(sb);

	*ret_entry = NULL;
	*inplace = 0;
	entry = nova_get_write_entry(sb, si, start_blk);
	if (entry) {
		/* We can do inplace write. Find contiguous blocks */
		if (entry->reassigned == 0)
			ent_blks = entry->num_pages -
					(start_blk - entry->pgoff);
		else
			ent_blks = 1;

		if (ent_blks > num_blocks)
			ent_blks = num_blocks;

		*ret_entry = entry;

		if (entry->trans_id > latest_snapshot_trans_id)
			*inplace = 1;

	} else if (check_next) {
		/* Possible Hole */
		entry = nova_find_next_entry(sb, sih, start_blk);
		if (entry) {
			next_pgoff = entry->pgoff;
			if (next_pgoff <= start_blk) {
				nova_err(sb, "iblock %lu, entry pgoff %lu, "
						" num pages %lu\n", start_blk,
						next_pgoff, entry->num_pages);
				nova_print_inode_log(sb, inode);
				BUG();
				ent_blks = num_blocks;
				goto out;
			}
			ent_blks = next_pgoff - start_blk;
			if (ent_blks > num_blocks)
				ent_blks = num_blocks;
		} else {
			/* File grow */
			ent_blks = num_blocks;
		}
	}

	if (entry && ent_blks == 0) {
		nova_dbg("%s: %d\n", __func__, check_next);
		dump_stack();
	}

out:
	return ent_blks;
}

ssize_t nova_inplace_file_write(struct file *filp,
	const char __user *buf,	size_t len, loff_t *ppos, bool need_mutex)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode    *inode = mapping->host;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi;
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry entry_data;
	struct nova_inode_update update;
	ssize_t     written = 0;
	loff_t pos;
	size_t count, offset, copied, csummed, ret;
	unsigned long start_blk, num_blocks, ent_blks = 0;
	unsigned long total_blocks;
	unsigned long blocknr = 0;
	unsigned int data_bits;
	int allocated = 0;
	int inplace = 0;
	bool hole_fill = false;
	bool update_log = false;
	void* kmem;
	u64 blk_off;
	size_t bytes;
	long status = 0;
	timing_t inplace_write_time, memcpy_time;
	unsigned long step = 0;
	u64 begin_tail = 0;
	u64 trans_id;
	u64 entry_size;
	u32 time;

	if (len == 0)
		return 0;

	NOVA_START_TIMING(inplace_write_t, inplace_write_time);

	sb_start_write(inode->i_sb);
	if (need_mutex)
		inode_lock(inode);

	if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	pos = *ppos;

	if (filp->f_flags & O_APPEND)
		pos = i_size_read(inode);

	count = len;

	pi = nova_get_inode(sb, inode);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;

	/* offset in the actual block size block */

	ret = file_remove_privs(filp);
	if (ret) {
		goto out;
	}
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	time = CURRENT_TIME_SEC.tv_sec;

	nova_dbgv("%s: inode %lu, offset %lld, count %lu\n",
			__func__, inode->i_ino,	pos, count);

	trans_id = nova_get_trans_id(sb);
	update.tail = sih->log_tail;
	update.alter_tail = sih->alter_log_tail;
	while (num_blocks > 0) {
		hole_fill = false;
		offset = pos & (nova_inode_blk_size(pi) - 1);
		start_blk = pos >> sb->s_blocksize_bits;

		ent_blks = nova_check_existing_entry(sb, inode, num_blocks,
						start_blk, &entry, 1, &inplace);

		if (entry && inplace) {
			/* We can do inplace write. Find contiguous blocks */
			blocknr = get_nvmm(sb, sih, entry, start_blk);
			blk_off = blocknr << PAGE_SHIFT; 
			allocated = ent_blks;
		} else {
			/* Allocate blocks to fill hole */
			allocated = nova_new_data_blocks(sb, pi, &blocknr, ent_blks,
							start_blk, 0, 0);
			nova_dbg_verbose("%s: alloc %d blocks @ %lu\n", __func__,
							allocated, blocknr);

			if (allocated <= 0) {
				nova_dbg("%s alloc blocks failed!, %d\n", __func__,
								allocated);
				ret = allocated;
				goto out;
			}

			hole_fill = true;
			blk_off = nova_get_block_off(sb, blocknr, pi->i_blk_type);
		}

		step++;
		bytes = sb->s_blocksize * allocated - offset;
		if (bytes > count)
			bytes = count;

		kmem = nova_get_block(inode->i_sb, blk_off);
		if (hole_fill && (offset || ((offset + bytes) & (PAGE_SIZE - 1)) != 0))
			nova_handle_head_tail_blocks(sb, pi, inode, pos, bytes,
								kmem);

		/* Now copy from user buf */
//		nova_dbg("Write: %p\n", kmem);
		NOVA_START_TIMING(memcpy_w_nvmm_t, memcpy_time);
		copied = bytes - memcpy_to_pmem_nocache(kmem + offset,
						buf, bytes);
		NOVA_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

		if (pos + copied > inode->i_size)
			entry_size = cpu_to_le64(pos + copied);
		else
			entry_size = cpu_to_le64(inode->i_size);

		/* Handle hole fill write */
		if (hole_fill) {
			nova_init_file_write_entry(sb, pi, &entry_data,
						trans_id, start_blk, allocated,
						blocknr, time, entry_size);

			ret = nova_append_file_write_entry(sb, pi, inode,
						&entry_data, &update);
			if (ret) {
				nova_dbg("%s: append inode entry failed\n", __func__);
				ret = -ENOSPC;
				goto out;
			}
		} else {
			/* Update existing entry */
			entry->trans_id = trans_id;
			entry->mtime = cpu_to_le32(time);
			entry->size = entry_size;
			nova_update_entry_csum(entry);
			nova_update_alter_entry(sb, entry);
		}

		if ( (copied > 0) && (NOVA_SB(sb)->data_csum_base > 0) ) {
			csummed = copied - nova_update_cow_csum(inode, blocknr,
						(void *) buf, offset, copied);
			if (unlikely(csummed != copied)) {
				nova_dbg("%s: not all data bytes are "
					"checksummed! copied %zu, "
					"csummed %zu\n", __func__,
					copied, csummed);
			}
		}

		nova_dbgv("Write: %p, %lu\n", kmem, copied);
		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			buf += copied;
			count -= copied;
			num_blocks -= allocated;
		}
		if (unlikely(copied != bytes)) {
			nova_dbg("%s ERROR!: %p, bytes %lu, copied %lu\n",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0)
			break;

		if (hole_fill) {
			update_log = true;
			if (begin_tail == 0)
				begin_tail = update.curr_entry;
		}
	}

	nova_memunlock_inode(sb, pi);
	data_bits = blk_type_to_shift[pi->i_blk_type];
	sih->i_blocks += (total_blocks << (data_bits - sb->s_blocksize_bits));
	nova_memlock_inode(sb, pi);

	inode->i_blocks = sih->i_blocks;

	if (update_log) {
		nova_update_inode(sb, inode, pi, &update, 1);

		/* Update file tree */
		ret = nova_reassign_file_tree(sb, pi, sih, begin_tail);
		if (ret) {
			goto out;
		}
	}

	ret = written;
	NOVA_STATS_ADD(inplace_write_breaks, step);
	nova_dbgv("blocks: %lu, %lu\n", inode->i_blocks, sih->i_blocks);

	*ppos = pos;
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		sih->i_size = pos;
	}

out:
	if (ret < 0)
		nova_cleanup_incomplete_write(sb, pi, sih, blocknr, allocated,
						begin_tail, update.tail);

	if (need_mutex)
		inode_unlock(inode);
	sb_end_write(inode->i_sb);
	NOVA_END_TIMING(inplace_write_t, inplace_write_time);
	NOVA_STATS_ADD(inplace_write_bytes, written);
	return ret;
}

ssize_t nova_dax_file_write(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	if (inplace_data_updates) {
		return nova_inplace_file_write(filp, buf, len, ppos, true);	
	} else {
		return nova_cow_file_write(filp, buf, len, ppos, true);
	}
}

/*
 * return > 0, # of blocks mapped or allocated.
 * return = 0, if plain lookup failed.
 * return < 0, error case.
 */
int nova_dax_get_blocks(struct inode *inode, sector_t iblock,
	unsigned long max_blocks, u32 *bno, bool *new, bool *boundary,
	int create, bool taking_lock)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry = NULL;
	struct nova_file_write_entry entry_data;
	struct nova_inode_update update;
	u32 time;
	unsigned int data_bits;
	unsigned long nvmm = 0;
	unsigned long blocknr = 0;
	u64 trans_id;
	int num_blocks = 0;
	int inplace = 0;
	int allocated = 0;
	int locked = 0;
	int check_next = 1;
	int ret = 0;

	if (max_blocks == 0)
		return 0;

	nova_dbgv("%s: pgoff %lu, num %lu, create %d\n",
				__func__, iblock, max_blocks, create);

	if (taking_lock)
		check_next = 0;

again:
	num_blocks = nova_check_existing_entry(sb, inode, max_blocks,
					iblock, &entry, check_next, &inplace);

	if (entry) {
		if (create == 0 || inplace) {
			nvmm = get_nvmm(sb, sih, entry, iblock);
			nova_dbgv("%s: found pgoff %lu, block %lu\n",
					__func__, iblock, nvmm);
			goto out;
		}
	}

	if (create == 0) {
		num_blocks = 0;
		goto out1;
	}

	if (taking_lock && locked == 0) {
		inode_lock(inode);
		locked = 1;
		/* Check again incase someone has done it for us */
		check_next = 1;
		goto again;
	}

	pi = nova_get_inode(sb, inode);
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	time = CURRENT_TIME_SEC.tv_sec;
	trans_id = nova_get_trans_id(sb);
	update.tail = sih->log_tail;
	update.alter_tail = sih->alter_log_tail;

	/* Return initialized blocks to the user */
	allocated = nova_new_data_blocks(sb, pi, &blocknr, num_blocks,
						iblock, 1, 1);
	if (allocated <= 0) {
		nova_dbg("%s alloc blocks failed %d\n", __func__,
							allocated);
		ret = allocated;
		goto out;
	}

	num_blocks = allocated;
	/* Do not extend file size */
	nova_init_file_write_entry(sb, pi, &entry_data,
					trans_id, iblock, num_blocks,
					blocknr, time, inode->i_size);

	ret = nova_append_file_write_entry(sb, pi, inode,
				&entry_data, &update);
	if (ret) {
		nova_dbg("%s: append inode entry failed\n", __func__);
		ret = -ENOSPC;
		goto out;
	}

	nvmm = blocknr;
	data_bits = blk_type_to_shift[pi->i_blk_type];
	sih->i_blocks += (num_blocks << (data_bits - sb->s_blocksize_bits));

	nova_update_inode(sb, inode, pi, &update, 1);

	ret = nova_reassign_file_tree(sb, pi, sih, update.curr_entry);
	if (ret)
		goto out;

	inode->i_blocks = sih->i_blocks;

//	set_buffer_new(bh);
out:
	if (ret < 0) {
		nova_cleanup_incomplete_write(sb, pi, sih, blocknr, allocated,
						0, update.tail);
		num_blocks = ret;
		goto out1;
	}

	*bno = nvmm;
//	if (num_blocks > 1)
//		bh->b_size = sb->s_blocksize * num_blocks;

out1:
	if (taking_lock && locked)
		inode_unlock(inode);

	return num_blocks;
}

#if 0
int nova_dax_get_block_nolock(struct inode *inode, sector_t iblock,
	struct buffer_head *bh, int create)
{
	unsigned long max_blocks = bh->b_size >> inode->i_blkbits;
	int ret;
	timing_t gb_time;

	NOVA_START_TIMING(dax_get_block_t, gb_time);

	ret = nova_dax_get_blocks(inode, iblock, max_blocks,
						bh, create, false);
	if (ret > 0) {
		bh->b_size = ret << inode->i_blkbits;
		ret = 0;
	}
	NOVA_END_TIMING(dax_get_block_t, gb_time);
	return ret;
}

int nova_dax_get_block_lock(struct inode *inode, sector_t iblock,
	struct buffer_head *bh, int create)
{
	unsigned long max_blocks = bh->b_size >> inode->i_blkbits;
	int ret;
	timing_t gb_time;

	NOVA_START_TIMING(dax_get_block_t, gb_time);

	ret = nova_dax_get_blocks(inode, iblock, max_blocks,
						bh, create, true);
	if (ret > 0) {
		bh->b_size = ret << inode->i_blkbits;
		ret = 0;
	}
	NOVA_END_TIMING(dax_get_block_t, gb_time);
	return ret;
}

static ssize_t nova_flush_mmap_to_nvmm(struct super_block *sb,
	struct inode *inode, struct nova_inode *pi, loff_t pos,
	size_t count, void *kmem, unsigned long blocknr)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned long start_blk;
	unsigned long cache_addr;
	u64 nvmm_block;
	void *nvmm_addr;
	loff_t offset;
	size_t bytes, copied, csummed;
	ssize_t written = 0;
	int status = 0;
	ssize_t ret;

	while (count) {
		start_blk = pos >> sb->s_blocksize_bits;
		offset = pos & (sb->s_blocksize - 1);
		bytes = sb->s_blocksize - offset;
		if (bytes > count)
			bytes = count;

		cache_addr = nova_get_cache_addr(sb, si, start_blk);
		if (cache_addr == 0) {
			nova_dbg("%s: ino %lu %lu mmap page %lu not found!\n",
					__func__, inode->i_ino, sih->ino, start_blk);
			nova_dbg("mmap pages %lu\n", sih->mmap_pages);
			ret = -EINVAL;
			goto out;
		}

		nvmm_block = MMAP_ADDR(cache_addr);
		nvmm_addr = nova_get_block(sb, nvmm_block);
		copied = bytes - memcpy_to_pmem_nocache(kmem + offset,
				nvmm_addr + offset, bytes);

		if ( (copied > 0) && (NOVA_SB(sb)->data_csum_base > 0) ) {
			csummed = copied - nova_update_cow_csum(inode,
				blocknr, nvmm_addr + offset, offset, copied);
			if (unlikely(csummed != copied)) {
				nova_dbg("%s: not all data bytes are "
					"checksummed! copied %zu, "
					"csummed %zu\n", __func__,
					copied, csummed);
			}
		}

		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			count -= copied;
			blocknr += (offset + copied) >> sb->s_blocksize_bits;
			kmem += offset + copied;
		}
		if (unlikely(copied != bytes)) {
			nova_dbg("%s ERROR!: %p, bytes %lu, copied %lu\n",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0) {
			ret = status;
			goto out;
		}
	}
	ret = written;
out:
	return ret;
}

ssize_t nova_copy_to_nvmm(struct super_block *sb, struct inode *inode,
	struct nova_inode *pi, loff_t pos, size_t count, u64 *begin,
	u64 *end)
{
	struct nova_file_write_entry entry_data;
	unsigned long start_blk, num_blocks;
	unsigned long blocknr = 0;
	unsigned long total_blocks;
	unsigned int data_bits;
	int allocated = 0;
	u64 curr_entry;
	ssize_t written = 0;
	int ret;
	void *kmem;
	size_t bytes, copied;
	loff_t offset;
	int status = 0;
	u64 temp_tail = 0, begin_tail = 0;
	u64 trans_id;
	u32 time;
	timing_t memcpy_time, copy_to_nvmm_time;

	NOVA_START_TIMING(copy_to_nvmm_t, copy_to_nvmm_time);
	sb_start_write(inode->i_sb);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	time = CURRENT_TIME_SEC.tv_sec;

	nova_dbgv("%s: ino %lu, block %llu, offset %lu, count %lu\n",
		__func__, inode->i_ino, pos >> sb->s_blocksize_bits,
		(unsigned long)offset, count);

	trans_id = nova_get_trans_id(sb);
	temp_tail = *end;
	while (num_blocks > 0) {
		offset = pos & (nova_inode_blk_size(pi) - 1);
		start_blk = pos >> sb->s_blocksize_bits;
		allocated = nova_new_data_blocks(sb, pi, &blocknr, num_blocks,
						start_blk, 0, 0);
		if (allocated <= 0) {
			nova_dbg("%s alloc blocks failed %d\n", __func__,
								allocated);
			ret = allocated;
			goto out;
		}

		bytes = sb->s_blocksize * allocated - offset;
		if (bytes > count)
			bytes = count;

		kmem = nova_get_block(inode->i_sb,
			nova_get_block_off(sb, blocknr,	pi->i_blk_type));

		if (offset || ((offset + bytes) & (PAGE_SIZE - 1)))
			nova_handle_head_tail_blocks(sb, pi, inode, pos,
							bytes, kmem);

		NOVA_START_TIMING(memcpy_w_wb_t, memcpy_time);
		copied = nova_flush_mmap_to_nvmm(sb, inode, pi, pos, bytes,
							kmem, blocknr);
		NOVA_END_TIMING(memcpy_w_wb_t, memcpy_time);

		memset(&entry_data, 0, sizeof(struct nova_file_write_entry));
		entry_data.entry_type = FILE_WRITE;
		entry_data.reassigned = 0;
		entry_data.trans_id = trans_id;
		entry_data.pgoff = cpu_to_le64(start_blk);
		entry_data.num_pages = cpu_to_le32(allocated);
		entry_data.invalid_pages = 0;
		entry_data.block = cpu_to_le64(nova_get_block_off(sb, blocknr,
							pi->i_blk_type));
		/* FIXME: should we use the page cache write time? */
		entry_data.mtime = cpu_to_le32(time);

		entry_data.size = cpu_to_le64(inode->i_size);

		curr_entry = nova_append_file_write_entry(sb, pi, inode,
						&entry_data, temp_tail);
		if (curr_entry == 0) {
			nova_dbg("%s: append inode entry failed\n", __func__);
			ret = -ENOSPC;
			goto out;
		}

		nova_dbgv("Write: %p, %ld\n", kmem, copied);
		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			count -= copied;
			num_blocks -= allocated;
		}
		if (unlikely(copied != bytes)) {
			nova_dbg("%s ERROR!: %p, bytes %lu, copied %lu\n",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0) {
			ret = status;
			goto out;
		}

		if (begin_tail == 0)
			begin_tail = curr_entry;
		temp_tail = curr_entry + sizeof(struct nova_file_write_entry);
	}

	nova_memunlock_inode(sb, pi);
	data_bits = blk_type_to_shift[pi->i_blk_type];
	sih->i_blocks += (total_blocks << (data_bits - sb->s_blocksize_bits));
	nova_memlock_inode(sb, pi);
	inode->i_blocks = sih->i_blocks;

	*begin = begin_tail;
	*end = temp_tail;

	ret = written;
out:
	if (ret < 0)
		nova_cleanup_incomplete_write(sb, pi, sih, blocknr, allocated,
						begin_tail, temp_tail);

	sb_end_write(inode->i_sb);
	NOVA_END_TIMING(copy_to_nvmm_t, copy_to_nvmm_time);
	return ret;
}

static int nova_get_nvmm_pfn(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info *si, u64 nvmm, pgoff_t pgoff,
	vm_flags_t vm_flags, void **kmem, unsigned long *pfn)
{
	struct nova_inode_info_header *sih = &si->header;
	u64 mmap_block;
	unsigned long cache_addr = 0;
	unsigned long blocknr = 0;
	void *mmap_addr;
	void *nvmm_addr;
	int ret;

	cache_addr = nova_get_cache_addr(sb, si, pgoff);

	if (cache_addr) {
		mmap_block = MMAP_ADDR(cache_addr);
		mmap_addr = nova_get_block(sb, mmap_block);
	} else {
		ret = nova_new_data_blocks(sb, pi, &blocknr, 1,
						pgoff, 0, 1);

		if (ret <= 0) {
			nova_dbg("%s alloc blocks failed %d\n",
					__func__, ret);
			return ret;
		}

		mmap_block = blocknr << PAGE_SHIFT;
		mmap_addr = nova_get_block(sb, mmap_block);

		if (vm_flags & VM_WRITE)
			mmap_block |= MMAP_WRITE_BIT;

		nova_dbgv("%s: inode %lu, pgoff %lu, mmap block 0x%llx\n",
			__func__, sih->ino, pgoff, mmap_block);

		ret = radix_tree_insert(&sih->cache_tree, pgoff,
					(void *)mmap_block);
		if (ret) {
			nova_dbg("%s: ERROR %d\n", __func__, ret);
			return ret;
		}

		sih->mmap_pages++;
		if (nvmm) {
			/* Copy from NVMM to dram */
			nvmm_addr = nova_get_block(sb, nvmm);
			memcpy(mmap_addr, nvmm_addr, PAGE_SIZE);
		} else {
			memset(mmap_addr, 0, PAGE_SIZE);
		}
	}

	*kmem = mmap_addr;
	*pfn = nova_get_pfn(sb, mmap_block);

	return 0;
}

static int nova_get_mmap_addr(struct inode *inode, struct vm_area_struct *vma,
	pgoff_t pgoff, int create, void **kmem, unsigned long *pfn)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *pi;
	u64 nvmm;
	vm_flags_t vm_flags = vma->vm_flags;
	int ret;

	pi = nova_get_inode(sb, inode);

	nvmm = nova_find_nvmm_block(sb, si, NULL, pgoff);

	ret = nova_get_nvmm_pfn(sb, pi, si, nvmm, pgoff, vm_flags,
						kmem, pfn);

	if (vm_flags & VM_WRITE) {
		if (pgoff < sih->low_dirty)
			sih->low_dirty = pgoff;
		if (pgoff > sih->high_dirty)
			sih->high_dirty = pgoff;
	}

	return ret;
}

/* OOM err return with dax file fault handlers doesn't mean anything.
 * It would just cause the OS to go an unnecessary killing spree !
 */
static int __nova_dax_file_fault(struct vm_area_struct *vma,
				  struct vm_fault *vmf)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	pgoff_t size;
	void *dax_mem;
	unsigned long dax_pfn = 0;
	int err;
	int ret = VM_FAULT_SIGBUS;

	inode_lock(inode);
	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size) {
		nova_dbg("[%s:%d] pgoff >= size(SIGBUS). vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx), size 0x%lx\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->virtual_address, size);
		goto out;
	}

	err = nova_get_mmap_addr(inode, vma, vmf->pgoff, 1,
						&dax_mem, &dax_pfn);
	if (unlikely(err)) {
		nova_dbg("[%s:%d] get_mmap_addr failed. vm_start(0x%lx),"
			" vm_end(0x%lx), pgoff(0x%lx), VA(%lx)\n",
			__func__, __LINE__, vma->vm_start, vma->vm_end,
			vmf->pgoff, (unsigned long)vmf->virtual_address);
		goto out;
	}

	nova_dbgv("%s flags: vma 0x%lx, vmf 0x%x\n",
			__func__, vma->vm_flags, vmf->flags);

	nova_dbgv("DAX mmap: inode %lu, vm_start(0x%lx), vm_end(0x%lx), "
			"pgoff(0x%lx), vma pgoff(0x%lx), "
			"VA(0x%lx)->PA(0x%lx)\n",
			inode->i_ino, vma->vm_start, vma->vm_end, vmf->pgoff,
			vma->vm_pgoff, (unsigned long)vmf->virtual_address,
			(unsigned long)dax_pfn << PAGE_SHIFT);

	if (dax_pfn == 0)
		goto out;

	err = vm_insert_mixed(vma, (unsigned long)vmf->virtual_address,
		__pfn_to_pfn_t(dax_pfn, PFN_DEV));

	if (err == -ENOMEM)
		goto out;
	/*
	 * err == -EBUSY is fine, we've raced against another thread
	 * that faulted-in the same page
	 */
	if (err != -EBUSY)
		BUG_ON(err);

	ret = VM_FAULT_NOPAGE;

out:
	inode_unlock(inode);
	return ret;
}

static int nova_dax_file_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int ret = 0;
	timing_t fault_time;

	NOVA_START_TIMING(mmap_fault_t, fault_time);
	ret = __nova_dax_file_fault(vma, vmf);
	NOVA_END_TIMING(mmap_fault_t, fault_time);
	return ret;
}
#endif

int nova_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
	unsigned flags, struct iomap *iomap, bool taking_lock)
{
	unsigned int blkbits = inode->i_blkbits;
	unsigned long first_block = offset >> blkbits;
	unsigned long max_blocks = (length + (1 << blkbits) - 1) >> blkbits;
	bool new = false, boundary = false;
	u32 bno;
	int ret;

	ret = nova_dax_get_blocks(inode, first_block, max_blocks, &bno, &new,
				&boundary, flags & IOMAP_WRITE, taking_lock);
	if (ret < 0)
		return ret;

	iomap->flags = 0;
	iomap->bdev = inode->i_sb->s_bdev;
	iomap->offset = (u64)first_block << blkbits;

	if (ret == 0) {
		iomap->type = IOMAP_HOLE;
		iomap->blkno = IOMAP_NULL_BLOCK;
		iomap->length = 1 << blkbits;
	} else {
		iomap->type = IOMAP_MAPPED;
		iomap->blkno = (sector_t)bno << (blkbits - 9);
		iomap->length = (u64)ret << blkbits;
		iomap->flags |= IOMAP_F_MERGED;
	}

	if (new)
		iomap->flags |= IOMAP_F_NEW;
	return 0;
}

int nova_iomap_end(struct inode *inode, loff_t offset, loff_t length,
	ssize_t written, unsigned flags, struct iomap *iomap)
{
	if (iomap->type == IOMAP_MAPPED &&
			written < length &&
			(flags & IOMAP_WRITE))
		truncate_pagecache(inode, inode->i_size);
	return 0;
}


static int nova_iomap_begin_lock(struct inode *inode, loff_t offset,
	loff_t length, unsigned flags, struct iomap *iomap)
{
	return nova_iomap_begin(inode, offset, length, flags, iomap, true);
}

static struct iomap_ops nova_iomap_ops_lock = {
	.iomap_begin	= nova_iomap_begin_lock,
	.iomap_end	= nova_iomap_end,
};

static int nova_dax_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int ret = 0;
	timing_t fault_time;

	NOVA_START_TIMING(mmap_fault_t, fault_time);

	ret = dax_iomap_fault(vma, vmf, &nova_iomap_ops_lock);

	NOVA_END_TIMING(mmap_fault_t, fault_time);
	return ret;
}

static int nova_dax_pmd_fault(struct vm_area_struct *vma, unsigned long addr,
	pmd_t *pmd, unsigned int flags)
{
	int ret = 0;
	timing_t fault_time;

	NOVA_START_TIMING(mmap_fault_t, fault_time);

	ret = dax_iomap_pmd_fault(vma, addr, pmd, flags, &nova_iomap_ops_lock);

	NOVA_END_TIMING(mmap_fault_t, fault_time);
	return ret;
}

static int nova_dax_pfn_mkwrite(struct vm_area_struct *vma,
	struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vma->vm_file);
	loff_t size;
	int ret = 0;
	timing_t fault_time;

	NOVA_START_TIMING(mmap_fault_t, fault_time);

	inode_lock(inode);
	size = (i_size_read(inode) + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (vmf->pgoff >= size)
		ret = VM_FAULT_SIGBUS;
	else
		ret = dax_pfn_mkwrite(vma, vmf);
	inode_unlock(inode);

	NOVA_END_TIMING(mmap_fault_t, fault_time);
	return ret;
}

static const struct vm_operations_struct nova_dax_vm_ops = {
	.fault	= nova_dax_fault,
	.pmd_fault = nova_dax_pmd_fault,
	.page_mkwrite = nova_dax_fault,
	.pfn_mkwrite = nova_dax_pfn_mkwrite,
};

int nova_dax_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);

	vma->vm_flags |= VM_MIXEDMAP | VM_HUGEPAGE;

	vma->vm_ops = &nova_dax_vm_ops;
	nova_dbg_mmap4k("[%s:%d] MMAP 4KPAGE vm_start(0x%lx),"
			" vm_end(0x%lx), vm_flags(0x%lx), "
			"vm_page_prot(0x%lx)\n", __func__,
			__LINE__, vma->vm_start, vma->vm_end,
			vma->vm_flags, pgprot_val(vma->vm_page_prot));

	return 0;
}


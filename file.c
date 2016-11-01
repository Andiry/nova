/*
 * BRIEF DESCRIPTION
 *
 * File operations for files.
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

#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <asm/mman.h>
#include "nova.h"

static inline int nova_can_set_blocksize_hint(struct inode *inode,
	struct nova_inode *pi, loff_t new_size)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	/* Currently, we don't deallocate data blocks till the file is deleted.
	 * So no changing blocksize hints once allocation is done. */
	if (sih->i_size > 0)
		return 0;
	return 1;
}

int nova_set_blocksize_hint(struct super_block *sb, struct inode *inode,
	struct nova_inode *pi, loff_t new_size)
{
	unsigned short block_type;

	if (!nova_can_set_blocksize_hint(inode, pi, new_size))
		return 0;

	if (new_size >= 0x40000000) {   /* 1G */
		block_type = NOVA_BLOCK_TYPE_1G;
		goto hint_set;
	}

	if (new_size >= 0x200000) {     /* 2M */
		block_type = NOVA_BLOCK_TYPE_2M;
		goto hint_set;
	}

	/* defaulting to 4K */
	block_type = NOVA_BLOCK_TYPE_4K;

hint_set:
	nova_dbg_verbose(
		"Hint: new_size 0x%llx, i_size 0x%llx\n",
		new_size, pi->i_size);
	nova_dbg_verbose("Setting the hint to 0x%x\n", block_type);
	nova_memunlock_inode(sb, pi);
	pi->i_blk_type = block_type;
	nova_memlock_inode(sb, pi);
	return 0;
}

static loff_t nova_llseek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	int retval;

	if (origin != SEEK_DATA && origin != SEEK_HOLE)
		return generic_file_llseek(file, offset, origin);

	mutex_lock(&inode->i_mutex);
	switch (origin) {
	case SEEK_DATA:
		retval = nova_find_region(inode, &offset, 0);
		if (retval) {
			mutex_unlock(&inode->i_mutex);
			return retval;
		}
		break;
	case SEEK_HOLE:
		retval = nova_find_region(inode, &offset, 1);
		if (retval) {
			mutex_unlock(&inode->i_mutex);
			return retval;
		}
		break;
	}

	if ((offset < 0 && !(file->f_mode & FMODE_UNSIGNED_OFFSET)) ||
	    offset > inode->i_sb->s_maxbytes) {
		mutex_unlock(&inode->i_mutex);
		return -EINVAL;
	}

	if (offset != file->f_pos) {
		file->f_pos = offset;
		file->f_version = 0;
	}

	mutex_unlock(&inode->i_mutex);
	return offset;
}

#if 0
static inline int nova_check_page_dirty(struct super_block *sb,
	unsigned long addr)
{
	return IS_MAP_WRITE(addr);
}

static unsigned long nova_get_dirty_range(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info *si, loff_t *start,
	loff_t end)
{
	unsigned long flush_bytes = 0;
	unsigned long bytes;
	unsigned long cache_addr = 0;
	pgoff_t pgoff;
	loff_t offset;
	loff_t dirty_start;
	loff_t temp = *start;

	nova_dbgv("%s: inode %llu, start %llu, end %llu\n",
			__func__, pi->nova_ino, *start, end);

	dirty_start = temp;
	while (temp < end) {
		pgoff = temp >> PAGE_SHIFT;
		offset = temp & ~PAGE_MASK;
		bytes = sb->s_blocksize - offset;
		if (bytes > (end - temp))
			bytes = end - temp;

		cache_addr = nova_get_cache_addr(sb, si, pgoff);
		if (cache_addr && nova_check_page_dirty(sb, cache_addr)) {
			if (flush_bytes == 0)
				dirty_start = temp;
			flush_bytes += bytes;
		} else {
			if (flush_bytes)
				break;
		}
		temp += bytes;
	}

	if (flush_bytes == 0)
		*start = end;
	else
		*start = dirty_start;

	return flush_bytes;
}

static void nova_get_sync_range(struct nova_inode_info_header *sih,
	loff_t *start, loff_t *end)
{
	unsigned long start_blk, end_blk;
	unsigned long low_blk, high_blk;

	start_blk = *start >> PAGE_SHIFT;
	end_blk = *end >> PAGE_SHIFT;

	low_blk = sih->low_dirty;
	high_blk = sih->high_dirty;

	if (start_blk < low_blk)
		*start = low_blk << PAGE_SHIFT;
	if (end_blk > high_blk)
		*end = (high_blk + 1) << PAGE_SHIFT;
}

/* This function is called by both msync() and fsync().
 * TODO: Check if we can avoid calling nova_flush_buffer() for fsync. We use
 * movnti to write data to files, so we may want to avoid doing unnecessary
 * nova_flush_buffer() on fsync() */
int nova_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	/* Sync from start to end[inclusive] */
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi;
	unsigned long start_blk, end_blk;
	u64 end_tail = 0, begin_tail = 0;
	u64 begin_temp = 0, end_temp = 0;
	int ret = 0;
	loff_t sync_start, sync_end;
	loff_t isize;
	timing_t fsync_time;

	NOVA_START_TIMING(fsync_t, fsync_time);
	if (!mapping_mapped(mapping))
		goto out;

	mutex_lock(&inode->i_mutex);

	/* Check the dirty range */
	pi = nova_get_inode(sb, inode);

	end += 1; /* end is inclusive. We like our indices normal please! */

	isize = i_size_read(inode);

	if ((unsigned long)end > (unsigned long)isize)
		end = isize;
	if (!isize || (start >= end))
	{
		nova_dbg_verbose("[%s:%d] : (ERR) isize(%llx), start(%llx),"
			" end(%llx)\n", __func__, __LINE__, isize, start, end);
		NOVA_END_TIMING(fsync_t, fsync_time);
		mutex_unlock(&inode->i_mutex);
		return 0;
	}

	nova_get_sync_range(sih, &start, &end);
	start_blk = start >> PAGE_SHIFT;
	end_blk = end >> PAGE_SHIFT;

	nova_dbgv("%s: start %llu, end %llu, size %llu, "
			" start_blk %lu, end_blk %lu\n",
			__func__, start, end, isize, start_blk,
			end_blk);

	sync_start = start;
	sync_end = end;
	end_temp = pi->log_tail;

	do {
		unsigned long nr_flush_bytes = 0;

		nr_flush_bytes = nova_get_dirty_range(sb, pi, si, &start, end);

		nova_dbgv("start %llu, flush bytes %lu\n",
				start, nr_flush_bytes);
		if (nr_flush_bytes) {
			nova_copy_to_nvmm(sb, inode, pi, start,
				nr_flush_bytes, &begin_temp, &end_temp);
			if (begin_tail == 0)
				begin_tail = begin_temp;
		}

		start += nr_flush_bytes;
	} while (start < end);

	end_tail = end_temp;
	if (begin_tail && end_tail && end_tail != pi->log_tail) {
		nova_update_tail(pi, end_tail);

		/* Free the overlap blocks after the write is committed */
		ret = nova_reassign_file_tree(sb, pi, sih, begin_tail);

		inode->i_blocks = sih->i_blocks;
	}

	mutex_unlock(&inode->i_mutex);

out:
	NOVA_END_TIMING(fsync_t, fsync_time);

	return ret;
}
#endif

/* This function is called by both msync() and fsync().
 * TODO: Check if we can avoid calling nova_flush_buffer() for fsync. We use
 * movnti to write data to files, so we may want to avoid doing unnecessary
 * nova_flush_buffer() on fsync() */
int nova_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	/* Sync from start to end[inclusive] */
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry;
	int ret = 0;
	loff_t isize;
	timing_t fsync_time;

	NOVA_START_TIMING(fsync_t, fsync_time);

	/* No need to flush if the file is not mmaped */
	if (!mapping_mapped(mapping))
		goto persist;

	end += 1; /* end is inclusive. We like our indices normal please! */

	isize = i_size_read(inode);

	if ((unsigned long)end > (unsigned long)isize)
		end = isize;
	if (!isize || (start >= end))
	{
		nova_dbgv("[%s:%d] : (ERR) isize(%llx), start(%llx),"
			" end(%llx)\n", __func__, __LINE__, isize, start, end);
		NOVA_END_TIMING(fsync_t, fsync_time);
		return -ENODATA;
	}

	/* Align start and end to cacheline boundaries */
	start = start & CACHELINE_MASK;
	end = CACHELINE_ALIGN(end);
	do {
		unsigned long nvmm;
		unsigned long nr_flush_bytes = 0;
		unsigned long avail_bytes = 0;
		void *dax_mem;
		pgoff_t pgoff;
		loff_t offset;

		pgoff = start >> PAGE_SHIFT;
		offset = start & ~PAGE_MASK;

		entry = nova_get_write_entry(sb, si, pgoff);
		if (unlikely(entry == NULL)) {
			nova_dbgv("Found hole: pgoff %lu, inode size %lld\n",
					pgoff, isize);

			/* Jump the hole */
			entry = nova_find_next_entry(sb, sih, pgoff);
			if (!entry)
				goto persist;

			pgoff = entry->pgoff;
			start = pgoff << PAGE_SHIFT;
			offset = 0;

			if (start >= end)
				goto persist;
		}

		nr_flush_bytes = end - start;

		if (pgoff < entry->pgoff ||
				pgoff - entry->pgoff >= entry->num_pages) {
			nova_err(sb, "%s ERROR: %lu, entry pgoff %llu, num %u, "
				"blocknr %llu\n", __func__, pgoff, entry->pgoff,
				entry->num_pages, entry->block >> PAGE_SHIFT);
			NOVA_END_TIMING(fsync_t, fsync_time);
			return -EINVAL;
		}

		/* Find contiguous blocks */
		if (entry->invalid_pages == 0)
			avail_bytes = (entry->num_pages - (pgoff - entry->pgoff))
				* PAGE_SIZE - offset;
		else
			avail_bytes = PAGE_SIZE - offset;

		if (nr_flush_bytes > avail_bytes)
			nr_flush_bytes = avail_bytes;

		nvmm = get_nvmm(sb, sih, entry, pgoff);
		dax_mem = nova_get_block(sb, (nvmm << PAGE_SHIFT));

		nova_dbgv("start %llu, flush bytes %lu\n",
				start, nr_flush_bytes);
		if (nr_flush_bytes)
			nova_flush_buffer(dax_mem + offset, nr_flush_bytes, 0);

		start += nr_flush_bytes;
	} while (start < end);

persist:
	PERSISTENT_BARRIER();
	NOVA_END_TIMING(fsync_t, fsync_time);

	return ret;
}

/* This callback is called when a file is closed */
static int nova_flush(struct file *file, fl_owner_t id)
{
	PERSISTENT_BARRIER();
	return 0;
}

static int nova_open(struct inode *inode, struct file *filp)
{
	return generic_file_open(inode, filp);
}

static long nova_fallocate(struct file *file, int mode, loff_t offset,
			    loff_t len)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *pi;
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry entry_data;
	struct nova_inode_update update;
	unsigned long start_blk, num_blocks, ent_blks = 0;
	unsigned long total_blocks = 0;
	unsigned long blocknr = 0;
	unsigned long next_pgoff;
	unsigned long blockoff;
	unsigned int data_bits;
	loff_t new_size;
	long ret = 0;
	int blocksize_mask;
	int allocated = 0;
	bool update_log = false;
	timing_t fallocate_time;
	u64 blk_off;
	u64 begin_tail = 0;
	u64 trans_id;
	u32 time;

	/* No fallocate for CoW */
	if (inplace_data_updates == 0)
		return -EOPNOTSUPP;

	/* We only support the FALLOC_FL_KEEP_SIZE mode */
	if (mode & ~FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode))
		return -ENODEV;

	new_size = len + offset;
	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > inode->i_size) {
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			return ret;
	} else {
		new_size = inode->i_size;
	}

	nova_dbgv("%s: inode %lu, offset %lld, count %lld, mode 0x%x\n",
			__func__, inode->i_ino,	offset, len, mode);

	NOVA_START_TIMING(fallocate_t, fallocate_time);
	mutex_lock(&inode->i_mutex);

	pi = nova_get_inode(sb, inode);
	if (!pi) {
		ret = -EACCES;
		goto out;
	}

	inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;
	time = CURRENT_TIME_SEC.tv_sec;

	blocksize_mask = sb->s_blocksize - 1;
	start_blk = offset >> sb->s_blocksize_bits;
	blockoff = offset & blocksize_mask;
	num_blocks = (blockoff + len + blocksize_mask) >> sb->s_blocksize_bits;

	trans_id = nova_get_trans_id(sb);
	update.tail = pi->log_tail;
	update.alter_tail = pi->alter_log_tail;
	while (num_blocks > 0) {
		entry = nova_get_write_entry(sb, si, start_blk);

		if (entry) {
			/* Find contiguous blocks */
			if (entry->invalid_pages == 0)
				ent_blks = entry->num_pages -
						(start_blk - entry->pgoff);
			else
				ent_blks = 1;

			if (ent_blks > num_blocks)
				ent_blks = num_blocks;

			if (entry->size < new_size) {
				entry->size = new_size;
				nova_update_entry_csum(entry);
				nova_update_alter_entry(sb, entry);
			}
			allocated = ent_blks;
			goto next;
		}

		/* Possible Hole */
		entry = nova_find_next_entry(sb, sih, start_blk);
		if (entry) {
			next_pgoff = entry->pgoff;
			if (next_pgoff <= start_blk) {
				nova_err(sb, "entry pgoff %llu, num pages %u, "
					"blk %lu\n", entry->pgoff,
					entry->num_pages, start_blk);
				nova_print_nova_log(sb, pi);
				BUG();
				ret = -EINVAL;
				goto out;
			}
			ent_blks = next_pgoff - start_blk;
			if (ent_blks > num_blocks)
				ent_blks = num_blocks;
		} else {
			/* File grow */
			ent_blks = num_blocks;
		}

		/* Allocate zeroed blocks to fill hole */
		allocated = nova_new_data_blocks(sb, pi, &blocknr, ent_blks,
						start_blk, 1, 0);
		nova_dbgv("%s: alloc %d blocks @ %lu\n", __func__,
						allocated, blocknr);

		if (allocated <= 0) {
			nova_dbg("%s alloc blocks failed!, %d\n", __func__,
							allocated);
			ret = allocated;
			goto out;
		}

		blk_off = nova_get_block_off(sb, blocknr, pi->i_blk_type);

		/* Handle hole fill write */
		memset(&entry_data, 0, sizeof(struct nova_file_write_entry));
		entry_data.entry_type = FILE_WRITE;
		entry_data.reassigned = 0;
		entry_data.trans_id = trans_id;
		entry_data.pgoff = cpu_to_le64(start_blk);
		entry_data.num_pages = cpu_to_le32(allocated);
		entry_data.invalid_pages = 0;
		entry_data.block = cpu_to_le64(blk_off);
		entry_data.mtime = cpu_to_le32(time);
		entry_data.size = new_size;

		ret = nova_append_file_write_entry(sb, pi, inode,
					&entry_data, &update);
		if (ret) {
			nova_dbg("%s: append inode entry failed\n", __func__);
			ret = -ENOSPC;
			goto out;
		}

#if 0
		if (NOVA_SB(sb)->data_csum_base > 0) {
			csummed = copied - nova_update_cow_csum(inode, blocknr,
						(void *) buf, offset, copied);
			if (unlikely(csummed != copied)) {
				nova_dbg("%s: not all data bytes are "
					"checksummed! copied %zu, "
					"csummed %zu\n", __func__,
					copied, csummed);
			}
		}
#endif

		update_log = true;
		if (begin_tail == 0)
			begin_tail = update.curr_entry;

		total_blocks += allocated;
next:
		num_blocks -= allocated;
		start_blk += allocated;
	}

	nova_memunlock_inode(sb, pi);
	data_bits = blk_type_to_shift[pi->i_blk_type];
	sih->i_blocks += (total_blocks << (data_bits - sb->s_blocksize_bits));
	nova_memlock_inode(sb, pi);

	inode->i_blocks = sih->i_blocks;

	if (update_log) {
		nova_update_tail(pi, update.tail);
		nova_update_alter_tail(pi, update.alter_tail);

		/* Update file tree */
		ret = nova_reassign_file_tree(sb, pi, sih, begin_tail);
		if (ret) {
			goto out;
		}
	}

	nova_dbgv("blocks: %lu, %lu\n", inode->i_blocks, sih->i_blocks);

	if (ret || (mode & FALLOC_FL_KEEP_SIZE)) {
		pi->i_flags |= cpu_to_le32(NOVA_EOFBLOCKS_FL);
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > inode->i_size) {
		inode->i_size = new_size;
		sih->i_size = new_size;
	}

	nova_update_inode_checksum(pi);
	nova_update_alter_inode(sb, inode, pi);

out:
	if (ret < 0)
		nova_cleanup_incomplete_write(sb, pi, sih, blocknr, allocated,
						begin_tail, update.tail);

	mutex_unlock(&inode->i_mutex);
	NOVA_END_TIMING(fallocate_t, fallocate_time);
	return ret;
}

const struct file_operations nova_dax_file_operations = {
	.llseek			= nova_llseek,
	.read			= nova_dax_file_read,
	.write			= nova_dax_file_write,
	.read_iter		= generic_file_read_iter,
	.write_iter		= generic_file_write_iter,
	.mmap			= nova_dax_file_mmap,
	.open			= nova_open,
	.fsync			= nova_fsync,
	.flush			= nova_flush,
	.unlocked_ioctl		= nova_ioctl,
	.fallocate		= nova_fallocate,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= nova_compat_ioctl,
#endif
};

const struct inode_operations nova_file_inode_operations = {
	.setattr	= nova_notify_change,
	.getattr	= nova_getattr,
	.get_acl	= NULL,
};

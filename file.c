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
#include "inode.h"

static loff_t nova_llseek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	int retval;

	if (origin != SEEK_DATA && origin != SEEK_HOLE)
		return generic_file_llseek(file, offset, origin);

	sih_lock_shared(sih);
	switch (origin) {
	case SEEK_DATA:
		retval = nova_find_region(inode, &offset, 0);
		if (retval) {
			sih_unlock_shared(sih);
			return retval;
		}
		break;
	case SEEK_HOLE:
		retval = nova_find_region(inode, &offset, 1);
		if (retval) {
			sih_unlock_shared(sih);
			return retval;
		}
		break;
	}

	if ((offset < 0 && !(file->f_mode & FMODE_UNSIGNED_OFFSET)) ||
	    offset > inode->i_sb->s_maxbytes) {
		sih_unlock_shared(sih);
		return -ENXIO;
	}

	if (offset != file->f_pos) {
		file->f_pos = offset;
		file->f_version = 0;
	}

	sih_unlock_shared(sih);
	return offset;
}

/* This function is called by both msync() and fsync().
 * TODO: Check if we can avoid calling nova_flush_buffer() for fsync. We use
 * movnti to write data to files, so we may want to avoid doing unnecessary
 * nova_flush_buffer() on fsync()
 */
static int nova_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct address_space *mapping = file->f_mapping;
	unsigned long start_pgoff, end_pgoff;
	int ret = 0;
	timing_t fsync_time;

	NOVA_START_TIMING(fsync_t, fsync_time);

	if (datasync)
		NOVA_STATS_ADD(fdatasync, 1);

	/* No need to flush if the file is not mmaped */
	if (!mapping_mapped(mapping))
		goto persist;

	start_pgoff = start >> PAGE_SHIFT;
	end_pgoff = (end + 1) >> PAGE_SHIFT;
	nova_dbgv("%s: msync pgoff range %lu to %lu\n",
			__func__, start_pgoff, end_pgoff);

	ret = generic_file_fsync(file, start, end, datasync);

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
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	struct nova_inode *pi;
	struct nova_file_write_entry *entry;
	struct nova_file_write_item *entry_item;
	struct list_head item_head;
	struct nova_inode_update update;
	unsigned long start_blk, num_blocks, ent_blks = 0;
	unsigned long total_blocks = 0;
	unsigned long blocknr = 0;
	unsigned long blockoff;
	loff_t new_size;
	long ret = 0;
	int inplace = 0;
	int blocksize_mask;
	int allocated = 0;
	timing_t fallocate_time;
	u64 epoch_id;
	u32 time;

	/*
	 * Fallocate does not make much sence for CoW,
	 * but we still support it for DAX-mmap purpose.
	 */

	/* We only support the FALLOC_FL_KEEP_SIZE mode */
	if (mode & ~FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode))
		return -ENODEV;

	INIT_LIST_HEAD(&item_head);
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
	inode_lock(inode);
	sih_lock(sih);

	pi = nova_get_inode(sb, inode);
	if (!pi) {
		ret = -EACCES;
		goto out;
	}

	inode->i_mtime = inode->i_ctime = current_time(inode);
	time = current_time(inode).tv_sec;

	blocksize_mask = sb->s_blocksize - 1;
	start_blk = offset >> sb->s_blocksize_bits;
	blockoff = offset & blocksize_mask;
	num_blocks = (blockoff + len + blocksize_mask) >> sb->s_blocksize_bits;

	epoch_id = nova_get_epoch_id(sb);
	update.tail = sih->log_tail;
	while (num_blocks > 0) {
		ent_blks = nova_check_existing_entry(sb, inode, num_blocks,
						start_blk, &entry,
						1, epoch_id, &inplace);

		if (entry && inplace) {
			if (entry->size < new_size) {
				/* Update existing entry */
				entry->size = new_size;
				nova_persist_entry(entry);
			}
			allocated = ent_blks;
			put_write_entry(entry);
			goto next;
		} else if (entry) {
			put_write_entry(entry);
		}

		/* Allocate zeroed blocks to fill hole */
		allocated = nova_new_data_blocks(sb, sih, &blocknr, start_blk,
				 ent_blks, ALLOC_INIT_ZERO, ANY_CPU,
				 ALLOC_FROM_HEAD);
		nova_dbgv("%s: alloc %d blocks @ %lu\n", __func__,
						allocated, blocknr);

		if (allocated <= 0) {
			nova_dbg("%s alloc %lu blocks failed!, %d\n",
						__func__, ent_blks, allocated);
			ret = allocated;
			goto out;
		}

		entry_item = nova_alloc_file_write_item(sb);
		if (!entry_item) {
			ret = -ENOMEM;
			goto out;
		}

		/* Handle hole fill write */
		nova_init_file_write_item(sb, sih, entry_item, epoch_id,
					start_blk, allocated, blocknr,
					time, new_size);

		entry_item->need_free = 1;
		list_add_tail(&entry_item->list, &item_head);

		total_blocks += allocated;
next:
		num_blocks -= allocated;
		start_blk += allocated;
	}

	ret = nova_commit_writes_to_log(sb, pi, inode,
					&item_head, total_blocks);
	if (ret < 0) {
		nova_err(sb, "commit to log failed\n");
		goto out;
	}

	if (ret || (mode & FALLOC_FL_KEEP_SIZE)) {
		pi->i_flags |= cpu_to_le32(NOVA_EOFBLOCKS_FL);
		sih->i_flags |= NOVA_EOFBLOCKS_FL;
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > inode->i_size) {
		inode->i_size = new_size;
		sih->i_size = new_size;
	}

	nova_persist_inode(pi);

out:
	if (ret < 0)
		nova_cleanup_incomplete_write(sb, sih, &item_head);

	sih_unlock(sih);
	inode_unlock(inode);
	NOVA_END_TIMING(fallocate_t, fallocate_time);
	return ret;
}

static ssize_t nova_dax_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
//	struct inode *inode = iocb->ki_filp->f_mapping->host;
	ssize_t ret;
	timing_t read_iter_time;

	if (!iov_iter_count(to))
		return 0;

	NOVA_START_TIMING(read_iter_t, read_iter_time);

//	inode_lock_shared(inode);
	ret = dax_iomap_rw(iocb, to, &nova_iomap_ops);
//	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);
	NOVA_END_TIMING(read_iter_t, read_iter_time);
	return ret;
}

static ssize_t nova_dax_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	loff_t offset;
	size_t count;
	ssize_t ret;
	timing_t write_iter_time;

	NOVA_START_TIMING(write_iter_t, write_iter_time);
//	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out_unlock;

	ret = file_remove_privs(file);
	if (ret)
		goto out_unlock;

	ret = file_update_time(file);
	if (ret)
		goto out_unlock;

	count = iov_iter_count(from);
	offset = iocb->ki_pos;

	ret = dax_iomap_rw(iocb, from, &nova_iomap_ops);
	if (ret > 0 && iocb->ki_pos > i_size_read(inode)) {
		i_size_write(inode, iocb->ki_pos);
		sih->i_size = iocb->ki_pos;
		mark_inode_dirty(inode);
	}

out_unlock:
//	inode_unlock(inode);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	NOVA_END_TIMING(write_iter_t, write_iter_time);
	return ret;
}

static ssize_t
do_dax_mapping_read(struct file *filp, char __user *buf,
	size_t len, loff_t *ppos)
{
	struct inode *inode = filp->f_mapping->host;
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info_header *sih = NOVA_IH(inode);
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
		void *dax_mem = NULL;
		int zero = 0;

		/* nr is the maximum number of bytes to copy from this page */
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset)
				goto out;
		}

		entry = nova_get_write_entry(sb, sih, index);
		if (unlikely(entry == NULL)) {
			nova_dbgv("Required extent not found: pgoff %lu, inode size %lld\n",
				index, isize);
			nr = PAGE_SIZE;
			zero = 1;
			goto memcpy;
		}

		/* Find contiguous blocks */
		if (index < entry->pgoff ||
			index - entry->pgoff >= entry->num_pages) {
			nova_err(sb, "%s ERROR: %lu, entry pgoff %llu, num %u, blocknr %llu\n",
				__func__, index, entry->pgoff,
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

		NOVA_START_TIMING(memcpy_r_nvmm_t, memcpy_time);

		if (!zero)
			left = __copy_to_user(buf + copied,
						dax_mem + offset, nr);
		else
			left = __clear_user(buf + copied, nr);

		NOVA_END_TIMING(memcpy_r_nvmm_t, memcpy_time);

		if (entry)
			put_write_entry(entry);

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
	return copied ? copied : error;
}

/*
 * Wrappers. We need to use the read lock to avoid
 * concurrent truncate operation. No problem for write because we held
 * lock.
 */
static ssize_t nova_dax_file_read(struct file *filp, char __user *buf,
			    size_t len, loff_t *ppos)
{
//	struct inode *inode = filp->f_mapping->host;
//	struct nova_inode_info_header *sih = NOVA_IH(inode);
	ssize_t res;
	timing_t dax_read_time;

	NOVA_START_TIMING(dax_read_t, dax_read_time);
//	inode_lock_shared(inode);
//	sih_lock_shared(sih);
	res = do_dax_mapping_read(filp, buf, len, ppos);
//	sih_unlock_shared(sih);
//	inode_unlock_shared(inode);
	NOVA_END_TIMING(dax_read_t, dax_read_time);
	return res;
}

/*
 * Perform a COW write.   Must hold the inode lock before calling.
 */
static ssize_t do_nova_cow_file_write(struct file *filp,
	const char __user *buf,	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode	*inode = mapping->host;
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi;
	struct nova_file_write_item *entry_item;
	struct list_head item_head;
	struct nova_inode_update update;
	ssize_t	    written = 0;
	loff_t pos, pos_head, pos_tail;
	size_t count, offset, copied;
	unsigned long start_blk, num_blocks;
	unsigned long total_blocks;
	unsigned long blocknr = 0;
	int allocated = 0;
	void *kmem, *kmem_head = NULL, *kmem_tail = NULL;
	u64 file_size;
	size_t bytes, bytes_head, bytes_tail;
	long status = 0;
	timing_t cow_write_time, memcpy_time;
	unsigned long step = 0;
	ssize_t ret;
	u64 epoch_id;
	u32 time;


	if (len == 0)
		return 0;

//	sih_lock(sih);
	NOVA_START_TIMING(cow_write_t, cow_write_time);
	INIT_LIST_HEAD(&item_head);

	if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	pos = *ppos;

	if (filp->f_flags & O_APPEND)
		pos = i_size_read(inode);

	count = len;

	pi = nova_get_block(sb, sih->pi_addr);

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;
	start_blk = pos >> sb->s_blocksize_bits;

	/* offset in the actual block size block */

	ret = file_remove_privs(filp);
	if (ret)
		goto out;

	inode->i_ctime = inode->i_mtime = current_time(inode);
	time = current_time(inode).tv_sec;

	nova_dbgv("%s: inode %lu, offset %lld, count %lu\n",
			__func__, inode->i_ino,	pos, count);

	epoch_id = nova_get_epoch_id(sb);
	update.tail = sih->log_tail;
	while (num_blocks > 0) {
		offset = pos & (nova_inode_blk_size(sih) - 1);
		start_blk = pos >> sb->s_blocksize_bits;

		/* don't zero-out the allocated blocks */
		allocated = nova_new_data_blocks(sb, sih, &blocknr, start_blk,
				 num_blocks, ALLOC_NO_INIT, ANY_CPU,
				 ALLOC_FROM_HEAD);

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
			     nova_get_block_off(sb, blocknr, sih->i_blk_type));

		if (offset) {
			pos_head = pos;
			bytes_head = bytes;
			kmem_head = kmem;
		} else if (((offset + bytes) & (PAGE_SIZE - 1)) != 0)  {
			pos_tail = pos;
			bytes_tail = bytes;
			kmem_tail = kmem;
		}

		/* Now copy from user buf */
		//		nova_dbg("Write: %p\n", kmem);
		NOVA_START_TIMING(memcpy_w_nvmm_t, memcpy_time);
		copied = bytes - __copy_from_user_inatomic_nocache(kmem + offset,
						buf, bytes);
		NOVA_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

		if (pos + copied > inode->i_size)
			file_size = pos + copied;
		else
			file_size = inode->i_size;

		entry_item = nova_alloc_file_write_item(sb);
		if (!entry_item) {
			ret = -ENOMEM;
			goto out;
		}

		nova_init_file_write_item(sb, sih, entry_item, epoch_id,
					start_blk, allocated, blocknr, time,
					file_size);

		entry_item->need_free = 1;
		list_add_tail(&entry_item->list, &item_head);

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
	}

	sih_lock(sih);

	/* Handle head/tail blocks inside the lock */
	if (kmem_head) {
		ret = nova_handle_head_tail_blocks(sb, inode, pos_head,
						   bytes_head, kmem_head);
		if (ret) {
			sih_unlock(sih);
			goto out;
		}
	}

	if (kmem_tail) {
		ret = nova_handle_head_tail_blocks(sb, inode, pos_tail,
						   bytes_tail, kmem_tail);
		if (ret) {
			sih_unlock(sih);
			goto out;
		}
	}

	ret = nova_commit_writes_to_log(sb, pi, inode,
					&item_head, total_blocks);

	sih_unlock(sih);

	if (ret < 0) {
		nova_err(sb, "commit to log failed\n");
		goto out;
	}

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
		nova_cleanup_incomplete_write(sb, sih, &item_head);

	NOVA_END_TIMING(cow_write_t, cow_write_time);
	NOVA_STATS_ADD(cow_write_bytes, written);
//	sih_unlock(sih);

	return ret;
}

/*
 * Acquire locks and perform COW write.
 */
ssize_t nova_cow_file_write(struct file *filp,
	const char __user *buf,	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	int ret;

	if (len == 0)
		return 0;

	sb_start_write(inode->i_sb);
//	inode_lock(inode);

	if (mapping_mapped(mapping))
		ret = do_nova_inplace_file_write(filp, buf, len, ppos);
	else
		ret = do_nova_cow_file_write(filp, buf, len, ppos);

//	inode_unlock(inode);
	sb_end_write(inode->i_sb);

	return ret;
}


static ssize_t nova_dax_file_write(struct file *filp, const char __user *buf,
				   size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;

	if (test_opt(inode->i_sb, DATA_COW))
		return nova_cow_file_write(filp, buf, len, ppos);
	else
		return nova_inplace_file_write(filp, buf, len, ppos);
}


static int nova_dax_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_mapping->host;

	file_accessed(file);

	vma->vm_flags |= VM_MIXEDMAP;

	vma->vm_ops = &nova_dax_vm_ops;

	nova_dbg_mmap4k("[%s:%d] inode %lu, MMAP 4KPAGE vm_start(0x%lx), "
			"vm_end(0x%lx), vm pgoff %lu, %lu blocks, "
			"vm_flags(0x%lx), vm_page_prot(0x%lx)\n",
			__func__, __LINE__,
			inode->i_ino, vma->vm_start, vma->vm_end,
			vma->vm_pgoff,
			(vma->vm_end - vma->vm_start) >> PAGE_SHIFT,
			vma->vm_flags,
			pgprot_val(vma->vm_page_prot));

	return 0;
}


const struct file_operations nova_dax_file_operations = {
	.llseek		= nova_llseek,
	.read		= nova_dax_file_read,
	.write		= nova_dax_file_write,
	.read_iter	= nova_dax_read_iter,
	.write_iter	= nova_dax_write_iter,
	.mmap		= nova_dax_file_mmap,
	.open		= nova_open,
	.fsync		= nova_fsync,
	.flush		= nova_flush,
	.unlocked_ioctl	= nova_ioctl,
	.fallocate	= nova_fallocate,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= nova_compat_ioctl,
#endif
};

const struct inode_operations nova_file_inode_operations = {
	.setattr	= nova_notify_change,
	.getattr	= nova_getattr,
	.get_acl	= NULL,
};

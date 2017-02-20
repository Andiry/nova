/*
 * BRIEF DESCRIPTION
 *
 * Memory protection for the filesystem pages.
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

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/io.h>
#include "nova.h"

static inline void wprotect_disable(void)
{
	unsigned long cr0_val;

	cr0_val = read_cr0();
	cr0_val &= (~X86_CR0_WP);
	write_cr0(cr0_val);
}

static inline void wprotect_enable(void)
{
	unsigned long cr0_val;

	cr0_val = read_cr0();
	cr0_val |= X86_CR0_WP;
	write_cr0(cr0_val);
}

/* FIXME: Assumes that we are always called in the right order.
 * nova_writeable(vaddr, size, 1);
 * nova_writeable(vaddr, size, 0);
 */
int nova_writeable(void *vaddr, unsigned long size, int rw)
{
	static unsigned long flags;
	if (rw) {
		local_irq_save(flags);
		wprotect_disable();
	} else {
		wprotect_enable();
		local_irq_restore(flags);
	}
	return 0;
}

int nova_dax_mem_protect(struct super_block *sb, void *vaddr,
			  unsigned long size, int rw)
{
	if (!nova_is_wprotected(sb))
		return 0;
	return nova_writeable(vaddr, size, rw);
}

static int nova_update_entry_pfn(struct super_block *sb,
	struct vm_area_struct *vma, struct nova_file_write_entry *entry)
{
	unsigned long newflags;
	unsigned long addr;
	unsigned long size;
	unsigned long pfn;
	pgprot_t new_prot;

	addr = vma->vm_start + ((entry->pgoff - vma->vm_pgoff) << PAGE_SHIFT);
	pfn = nova_get_pfn(sb, entry->block);
	size = entry->num_pages << PAGE_SHIFT;

	newflags = vma->vm_flags | VM_WRITE;
	new_prot = vm_get_page_prot(newflags);

	return remap_pfn_range(vma, addr, pfn, size, new_prot);
}

static int nova_dax_mmap_update_pfn(struct super_block *sb,
	struct vm_area_struct *vma, struct nova_inode_info_header *sih,
	u64 begin_tail)
{
	struct nova_file_write_entry *entry_data;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct nova_file_write_entry);
	int ret;

	while (curr_p && curr_p != sih->log_tail) {
		if (is_last_entry(curr_p, entry_size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_err(sb, "%s: File inode %lu log is NULL!\n",
				__func__, sih->ino);
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

		ret = nova_update_entry_pfn(sb, vma, entry_data);
		if (ret) {
			nova_err(sb, "update_pfn return %d\n", ret);
			break;
		}
		curr_p += entry_size;
	}

	return ret;
}

int nova_mmap_to_new_blocks(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi;
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry entry_data;
	struct nova_inode_update update;
	unsigned long start_blk, num_blocks, end_blk;
	unsigned long entry_pgoff;
	unsigned long from_blocknr = 0;
	unsigned long blocknr = 0;
	unsigned long avail_blocks;
	unsigned long copy_blocks;
	u64 from_blockoff, to_blockoff;
	u64 latest_snapshot_trans_id;
	size_t copied;
	int allocated = 0;
	void *from_kmem;
	void *to_kmem;
	size_t bytes;
	timing_t memcpy_time;
	u64 begin_tail = 0;
	u64 trans_id;
	u64 entry_size;
	u32 time;
	int ret;

	start_blk = vma->vm_pgoff;
	num_blocks = (vma->vm_end - vma->vm_start) >> sb->s_blocksize_bits;
	end_blk = start_blk + num_blocks;
	if (start_blk >= end_blk)
		return 0;

	inode_lock(inode);

	pi = nova_get_inode(sb, inode);

	nova_dbgv("%s: inode %lu, vm_start(0x%lx), vm_end(0x%lx), "
			"vma pgoff(0x%lx)\n", __func__, inode->i_ino,
			vma->vm_start, vma->vm_end, vma->vm_pgoff);

	time = CURRENT_TIME_SEC.tv_sec;

	latest_snapshot_trans_id = nova_get_create_snapshot_trans_id(sb);

	if (latest_snapshot_trans_id == 0)
		latest_snapshot_trans_id = nova_get_latest_snapshot_trans_id(sb);

	trans_id = nova_get_trans_id(sb);
	update.tail = pi->log_tail;
	update.alter_tail = pi->alter_log_tail;
	while (start_blk < end_blk) {
		entry = nova_get_write_entry(sb, sih, start_blk);
		if (!entry) {
			nova_dbgv("%s: Found hole: pgoff %lu\n",
					__func__, start_blk);

			/* Jump the hole */
			entry = nova_find_next_entry(sb, sih, start_blk);
			if (!entry)
				break;

			start_blk = entry->pgoff;
			if (start_blk >= end_blk)
				break;
		}

		from_blocknr = get_nvmm(sb, sih, entry, start_blk);
		from_blockoff = nova_get_block_off(sb, from_blocknr,
						pi->i_blk_type);
		from_kmem = nova_get_block(sb, from_blockoff);

		if (entry->reassigned == 0)
			avail_blocks = entry->num_pages -
					(start_blk - entry->pgoff);
		else
			avail_blocks = 1;

		if (avail_blocks > end_blk - start_blk)
			avail_blocks = end_blk - start_blk;

		if (entry->trans_id > latest_snapshot_trans_id) {
			start_blk += avail_blocks;
			continue;
		}

		allocated = nova_new_data_blocks(sb, sih, &blocknr,
						avail_blocks, start_blk, 0, 0);
		nova_dbgv("%s: alloc %d blocks @ %lu\n", __func__,
						allocated, blocknr);

		if (allocated <= 0) {
			nova_dbg("%s alloc blocks failed!, %d\n",
						__func__, allocated);
			ret = allocated;
			goto out;
		}

		to_blockoff = nova_get_block_off(sb, blocknr,
						pi->i_blk_type);
		to_kmem = nova_get_block(sb, to_blockoff);
		entry_pgoff = start_blk;

		copy_blocks = allocated;

		bytes = sb->s_blocksize * copy_blocks;

		/* Now copy from user buf */
		NOVA_START_TIMING(memcpy_w_wb_t, memcpy_time);
		nova_memunlock_range(sb, to_kmem, bytes);
		copied = bytes - memcpy_to_pmem_nocache(to_kmem, from_kmem,
							bytes);
		nova_memlock_range(sb, to_kmem, bytes);
		NOVA_END_TIMING(memcpy_w_wb_t, memcpy_time);

		if (copied == bytes) {
			start_blk += copy_blocks;
		} else {
			nova_dbg("%s ERROR!: bytes %lu, copied %lu\n",
				__func__, bytes, copied);
			ret = -EFAULT;
			goto out;
		}

		entry_size = cpu_to_le64(inode->i_size);

		nova_init_file_write_entry(sb, sih, &entry_data,
					trans_id, entry_pgoff, copy_blocks,
					blocknr, time, entry_size);

		ret = nova_append_file_write_entry(sb, pi, inode,
					&entry_data, &update);
		if (ret) {
			nova_dbg("%s: append inode entry failed\n",
					__func__);
			ret = -ENOSPC;
			goto out;
		}

		if (begin_tail == 0)
			begin_tail = update.curr_entry;
	}

	if (begin_tail == 0)
		goto out;

	nova_memunlock_inode(sb, pi);
	nova_update_inode(sb, inode, pi, &update, 1);
	nova_memlock_inode(sb, pi);

	/* Update file tree */
	ret = nova_reassign_file_tree(sb, sih, begin_tail);
	if (ret) {
		goto out;
	}

	/* Update pfn and prot */
	ret = nova_dax_mmap_update_pfn(sb, vma, sih, begin_tail);
	if (ret) {
		goto out;
	}

//	nova_print_nova_log(sb, pi);

out:
	if (ret < 0)
		nova_cleanup_incomplete_write(sb, sih, blocknr, allocated,
						begin_tail, update.tail);

	inode_unlock(inode);
	return ret;
}

#ifdef MPROTECT_READ

static int nova_set_vma_read(struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long oldflags = vma->vm_flags;
	unsigned long newflags;
	pgprot_t new_page_prot;

	down_write(&mm->mmap_sem);

	newflags = oldflags & (~VM_WRITE);
	if (oldflags == newflags)
		goto out;

	nova_dbgv("Set vma %p read, start 0x%lx, end 0x%lx\n",
				vma, vma->vm_start,
				vma->vm_end);

	new_page_prot = vm_get_page_prot(newflags);
	change_protection(vma, vma->vm_start, vma->vm_end,
				new_page_prot, 0, 0);
	vma->original_write = 1;

out:
	up_write(&mm->mmap_sem);

	return 0;
}

int nova_set_vmas_readonly(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct vma_item *item;
	struct rb_node *temp;

	nova_dbgv("%s\n", __func__);
	spin_lock(&sbi->vma_lock);
	temp = rb_first(&sbi->vma_tree);
	while (temp) {
		item = container_of(temp, struct vma_item, node);
		temp = rb_next(temp);
		nova_set_vma_read(item->vma);
	}
	spin_unlock(&sbi->vma_lock);

	return 0;
}

int nova_destroy_vma_tree(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct vma_item *item;
	struct rb_node *temp;

	nova_dbgv("%s\n", __func__);
	spin_lock(&sbi->vma_lock);
	temp = rb_first(&sbi->vma_tree);
	while (temp) {
		item = container_of(temp, struct vma_item, node);
		temp = rb_next(temp);
		rb_erase(&item->node, &sbi->vma_tree);
		kfree(item);
	}
	spin_unlock(&sbi->vma_lock);

	return 0;
}

#else

int nova_set_vmas_readonly(struct super_block *sb)
{
	return 0;
}

int nova_destroy_vma_tree(struct super_block *sb)
{
	return 0;
}

#endif

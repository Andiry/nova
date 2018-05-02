/*
 * BRIEF DESCRIPTION
 *
 * Proc fs operations
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
#include "inode.h"

const char *proc_dirname = "fs/NOVA";
struct proc_dir_entry *nova_proc_root;

/* ====================== Statistics ======================== */
static int nova_seq_timing_show(struct seq_file *seq, void *v)
{
	int i;

	nova_get_timing_stats();

	seq_puts(seq, "=========== NOVA kernel timing stats ===========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		/* Title */
		if (Timingstring[i][0] == '=') {
			seq_printf(seq, "\n%s\n\n", Timingstring[i]);
			continue;
		}

		if (measure_timing || Timingstats[i]) {
			seq_printf(seq, "%s: count %llu, timing %llu, average %llu\n",
				Timingstring[i],
				Countstats[i],
				Timingstats[i],
				Countstats[i] ?
				Timingstats[i] / Countstats[i] : 0);
		} else {
			seq_printf(seq, "%s: count %llu\n",
				Timingstring[i],
				Countstats[i]);
		}
	}

	seq_puts(seq, "\n");
	return 0;
}

static int nova_seq_timing_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_timing_show, PDE_DATA(inode));
}

static ssize_t nova_seq_clear_stats(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct super_block *sb = PDE_DATA(inode);

	nova_clear_stats(sb);
	return len;
}

static const struct file_operations nova_seq_timing_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_timing_open,
	.read		= seq_read,
	.write		= nova_seq_clear_stats,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int nova_seq_IO_show(struct seq_file *seq, void *v)
{
	struct super_block *sb = seq->private;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long alloc_log_count = 0;
	unsigned long alloc_log_pages = 0;
	unsigned long alloc_data_count = 0;
	unsigned long alloc_data_pages = 0;
	unsigned long free_log_count = 0;
	unsigned long freed_log_pages = 0;
	unsigned long free_data_count = 0;
	unsigned long freed_data_pages = 0;
	int i;

	nova_get_timing_stats();
	nova_get_IO_stats();

	seq_puts(seq, "============ NOVA allocation stats ============\n\n");

	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);

		alloc_log_count += free_list->alloc_log_count;
		alloc_log_pages += free_list->alloc_log_pages;
		alloc_data_count += free_list->alloc_data_count;
		alloc_data_pages += free_list->alloc_data_pages;
		free_log_count += free_list->free_log_count;
		freed_log_pages += free_list->freed_log_pages;
		free_data_count += free_list->free_data_count;
		freed_data_pages += free_list->freed_data_pages;
	}

	seq_printf(seq, "alloc log count %lu, allocated log pages %lu\n"
		"alloc data count %lu, allocated data pages %lu\n"
		"free log count %lu, freed log pages %lu\n"
		"free data count %lu, freed data pages %lu\n",
		alloc_log_count, alloc_log_pages,
		alloc_data_count, alloc_data_pages,
		free_log_count, freed_log_pages,
		free_data_count, freed_data_pages);

	seq_printf(seq, "Fast GC %llu, check pages %llu, free pages %llu, average %llu\n",
		Countstats[fast_gc_t], IOstats[fast_checked_pages],
		IOstats[fast_gc_pages], Countstats[fast_gc_t] ?
			IOstats[fast_gc_pages] / Countstats[fast_gc_t] : 0);
	seq_printf(seq, "Thorough GC %llu, checked pages %llu, free pages %llu, average %llu\n",
		Countstats[thorough_gc_t],
		IOstats[thorough_checked_pages], IOstats[thorough_gc_pages],
		Countstats[thorough_gc_t] ?
			IOstats[thorough_gc_pages] / Countstats[thorough_gc_t]
			: 0);

	seq_puts(seq, "\n");

	seq_puts(seq, "================ NOVA I/O stats ================\n\n");
	seq_printf(seq, "Read %llu, bytes %llu, average %llu\n",
		Countstats[dax_read_t], IOstats[read_bytes],
		Countstats[dax_read_t] ?
			IOstats[read_bytes] / Countstats[dax_read_t] : 0);
	seq_printf(seq, "COW write %llu, bytes %llu, average %llu, write breaks %llu, average %llu\n",
		Countstats[cow_write_t], IOstats[cow_write_bytes],
		Countstats[cow_write_t] ?
			IOstats[cow_write_bytes] / Countstats[cow_write_t] : 0,
		IOstats[cow_write_breaks], Countstats[cow_write_t] ?
			IOstats[cow_write_breaks] / Countstats[cow_write_t]
			: 0);
	seq_printf(seq, "Inplace write %llu, bytes %llu, average %llu, write breaks %llu, average %llu\n",
		Countstats[inplace_write_t], IOstats[inplace_write_bytes],
		Countstats[inplace_write_t] ?
			IOstats[inplace_write_bytes] /
			Countstats[inplace_write_t] : 0,
		IOstats[inplace_write_breaks], Countstats[inplace_write_t] ?
			IOstats[inplace_write_breaks] /
			Countstats[inplace_write_t] : 0);
	seq_printf(seq, "Inplace write %llu, allocate new blocks %llu\n",
			Countstats[inplace_write_t],
			IOstats[inplace_new_blocks]);
	seq_printf(seq, "DAX get blocks %llu, allocate new blocks %llu\n",
			Countstats[dax_get_block_t], IOstats[dax_new_blocks]);
	seq_printf(seq, "Page fault %llu\n", Countstats[mmap_fault_t]);
	seq_printf(seq, "fsync %llu, fdatasync %llu\n",
			Countstats[fsync_t], IOstats[fdatasync]);

	seq_puts(seq, "\n");

	return 0;
}

static int nova_seq_IO_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_IO_show, PDE_DATA(inode));
}

static const struct file_operations nova_seq_IO_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_IO_open,
	.read		= seq_read,
	.write		= nova_seq_clear_stats,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int nova_seq_show_allocator(struct seq_file *seq, void *v)
{
	struct super_block *sb = seq->private;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;
	unsigned long log_pages = 0;
	unsigned long data_pages = 0;

	seq_puts(seq, "======== NOVA per-CPU allocator stats ========\n");
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		seq_printf(seq, "Free list %d: block start %lu, block end %lu, num_blocks %lu, num_free_blocks %lu, blocknode %lu\n",
			i, free_list->block_start, free_list->block_end,
			free_list->block_end - free_list->block_start + 1,
			free_list->num_free_blocks, free_list->num_blocknode);

		if (free_list->first_node) {
			seq_printf(seq, "First node %lu - %lu\n",
					free_list->first_node->range_low,
					free_list->first_node->range_high);
		}

		if (free_list->last_node) {
			seq_printf(seq, "Last node %lu - %lu\n",
					free_list->last_node->range_low,
					free_list->last_node->range_high);
		}

		seq_printf(seq, "Free list %d: alloc log count %lu, allocated log pages %lu, alloc data count %lu, allocated data pages %lu, free log count %lu, freed log pages %lu, free data count %lu, freed data pages %lu\n",
			   i,
			   free_list->alloc_log_count,
			   free_list->alloc_log_pages,
			   free_list->alloc_data_count,
			   free_list->alloc_data_pages,
			   free_list->free_log_count,
			   free_list->freed_log_pages,
			   free_list->free_data_count,
			   free_list->freed_data_pages);

		log_pages += free_list->alloc_log_pages;
		log_pages -= free_list->freed_log_pages;

		data_pages += free_list->alloc_data_pages;
		data_pages -= free_list->freed_data_pages;
	}

	seq_printf(seq, "\nCurrently used pmem pages: log %lu, data %lu\n",
			log_pages, data_pages);

	return 0;
}

static int nova_seq_allocator_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_show_allocator,
				PDE_DATA(inode));
}

static const struct file_operations nova_seq_allocator_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_allocator_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};


/* ====================== GC ======================== */


static int nova_seq_gc_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "Echo inode number to trigger garbage collection\n"
		   "    example: echo 34 > /proc/fs/NOVA/pmem0/gc\n");
	return 0;
}

static int nova_seq_gc_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_gc_show, PDE_DATA(inode));
}

static ssize_t nova_seq_gc(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	u64 target_inode_number;
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct super_block *sb = PDE_DATA(inode);
	struct inode *target_inode;
	struct nova_inode *target_pi;
	struct nova_inode_info_header *target_sih;

	int ret;
	char *_buf;
	int retval = len;

	_buf = kmalloc(len, GFP_KERNEL);
	if (_buf == NULL)  {
		retval = -ENOMEM;
		nova_dbg("%s: kmalloc failed\n", __func__);
		goto out;
	}

	if (copy_from_user(_buf, buf, len)) {
		retval = -EFAULT;
		goto out;
	}

	_buf[len] = 0;
	ret = kstrtoull(_buf, 0, &target_inode_number);
	if (ret) {
		nova_info("%s: Could not parse ino '%s'\n", __func__, _buf);
		return ret;
	}
	nova_info("%s: target_inode_number=%llu.", __func__,
		  target_inode_number);

	target_inode = nova_iget(sb, target_inode_number);
	if (target_inode == NULL) {
		nova_info("%s: inode %llu does not exist.", __func__,
			  target_inode_number);
		retval = -ENOENT;
		goto out;
	}

	target_pi = nova_get_inode(sb, target_inode);
	if (target_pi == NULL) {
		nova_info("%s: couldn't get nova inode %llu.", __func__,
			  target_inode_number);
		retval = -ENOENT;
		goto out;
	}

	target_sih = NOVA_IH(target_inode);

	nova_info("%s: got inode %llu @ 0x%p; pi=0x%p\n", __func__,
		  target_inode_number, target_inode, target_pi);

	nova_inode_log_fast_gc(sb, target_pi, target_sih,
			       0, 0, 0, 1);
	iput(target_inode);

out:
	kfree(_buf);
	return retval;
}

static const struct file_operations nova_seq_gc_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_gc_open,
	.read		= seq_read,
	.write		= nova_seq_gc,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* ====================== Setup/teardown======================== */
void nova_procfs_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (nova_proc_root)
		sbi->s_proc = proc_mkdir(sbi->s_bdev->bd_disk->disk_name,
					 nova_proc_root);

	if (sbi->s_proc) {
		proc_create_data("timing_stats", 0444, sbi->s_proc,
				 &nova_seq_timing_fops, sb);
		proc_create_data("IO_stats", 0444, sbi->s_proc,
				 &nova_seq_IO_fops, sb);
		proc_create_data("allocator", 0444, sbi->s_proc,
				 &nova_seq_allocator_fops, sb);
		proc_create_data("gc", 0444, sbi->s_proc,
				 &nova_seq_gc_fops, sb);
	}
}

void nova_procfs_exit(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (sbi->s_proc) {
		remove_proc_entry("timing_stats", sbi->s_proc);
		remove_proc_entry("IO_stats", sbi->s_proc);
		remove_proc_entry("allocator", sbi->s_proc);
		remove_proc_entry("gc", sbi->s_proc);
		remove_proc_entry(sbi->s_bdev->bd_disk->disk_name,
					nova_proc_root);
	}
}

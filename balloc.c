/*
 * NOVA persistent memory management
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
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#include <linux/fs.h>
#include <linux/bitops.h>
#include "nova.h"
#include "inode.h"

int nova_alloc_block_free_lists(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;

	sbi->free_lists = kcalloc(sbi->cpus, sizeof(struct free_list),
				  GFP_KERNEL);

	if (!sbi->free_lists)
		return -ENOMEM;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		free_list->block_free_tree = RB_ROOT;
		spin_lock_init(&free_list->s_lock);
		free_list->index = i;
	}

	return 0;
}

void nova_delete_free_lists(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	/* Each tree is freed in save_blocknode_mappings */
	kfree(sbi->free_lists);
	sbi->free_lists = NULL;
}

// Initialize a free list.  Each CPU gets an equal share of the block space to
// manage.
static void nova_init_free_list(struct super_block *sb,
	struct free_list *free_list, int index)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long per_list_blocks;

	per_list_blocks = sbi->num_blocks / sbi->cpus;

	free_list->block_start = per_list_blocks * index;
	free_list->block_end = free_list->block_start +
					per_list_blocks - 1;
	if (index == 0)
		free_list->block_start += sbi->head_reserved_blocks;
	if (index == sbi->cpus - 1)
		free_list->block_end -= sbi->tail_reserved_blocks;
}

struct nova_range_node *nova_alloc_blocknode_atomic(struct super_block *sb)
{
	return nova_alloc_range_node_atomic(sb);
}

struct nova_range_node *nova_alloc_blocknode(struct super_block *sb)
{
	return nova_alloc_range_node(sb);
}

void nova_free_blocknode(struct nova_range_node *node)
{
	nova_free_range_node(node);
}

void nova_init_blockmap(struct super_block *sb, int recovery)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct rb_root *tree;
	struct nova_range_node *blknode;
	struct free_list *free_list;
	int i;
	int ret;

	/* Divide the block range among per-CPU free lists */
	sbi->per_list_blocks = sbi->num_blocks / sbi->cpus;
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		tree = &(free_list->block_free_tree);
		nova_init_free_list(sb, free_list, i);

		/* For recovery, update these fields later */
		if (recovery == 0) {
			free_list->num_free_blocks = free_list->block_end -
						free_list->block_start + 1;

			blknode = nova_alloc_blocknode(sb);
			if (blknode == NULL)
				return;
			blknode->range_low = free_list->block_start;
			blknode->range_high = free_list->block_end;
			ret = nova_insert_blocktree(tree, blknode);
			if (ret) {
				nova_err(sb, "%s failed\n", __func__);
				nova_free_blocknode(blknode);
				return;
			}
			free_list->first_node = blknode;
			free_list->last_node = blknode;
			free_list->num_blocknode = 1;
		}

		nova_dbgv("%s: free list %d: block start %lu, end %lu, "
			  "%lu free blocks\n",
			  __func__, i,
			  free_list->block_start,
			  free_list->block_end,
			  free_list->num_free_blocks);
	}
}

static inline int nova_rbtree_compare_rangenode(struct nova_range_node *curr,
	unsigned long key, enum node_type type)
{
	if (type == NODE_DIR) {
		if (key < curr->hash)
			return -1;
		if (key > curr->hash)
			return 1;
		return 0;
	}

	/* Block and inode */
	if (key < curr->range_low)
		return -1;
	if (key > curr->range_high)
		return 1;

	return 0;
}

int nova_find_range_node(struct rb_root *tree, unsigned long key,
	enum node_type type, struct nova_range_node **ret_node)
{
	struct nova_range_node *curr = NULL;
	struct rb_node *temp;
	int compVal;
	int ret = 0;

	temp = tree->rb_node;

	while (temp) {
		curr = container_of(temp, struct nova_range_node, node);
		compVal = nova_rbtree_compare_rangenode(curr, key, type);

		if (compVal == -1) {
			temp = temp->rb_left;
		} else if (compVal == 1) {
			temp = temp->rb_right;
		} else {
			ret = 1;
			break;
		}
	}

	*ret_node = curr;
	return ret;
}


int nova_insert_range_node(struct rb_root *tree,
	struct nova_range_node *new_node, enum node_type type)
{
	struct nova_range_node *curr;
	struct rb_node **temp, *parent;
	int compVal;

	temp = &(tree->rb_node);
	parent = NULL;

	while (*temp) {
		curr = container_of(*temp, struct nova_range_node, node);
		compVal = nova_rbtree_compare_rangenode(curr,
					new_node->range_low, type);
		parent = *temp;

		if (compVal == -1) {
			temp = &((*temp)->rb_left);
		} else if (compVal == 1) {
			temp = &((*temp)->rb_right);
		} else {
			nova_dbg("%s: type %d entry %lu - %lu already exists: "
				"%lu - %lu\n",
				 __func__, type, new_node->range_low,
				new_node->range_high, curr->range_low,
				curr->range_high);
			return -EINVAL;
		}
	}

	rb_link_node(&new_node->node, parent, temp);
	rb_insert_color(&new_node->node, tree);

	return 0;
}

void nova_destroy_range_node_tree(struct super_block *sb,
	struct rb_root *tree)
{
	struct nova_range_node *curr;
	struct rb_node *temp;

	temp = rb_first(tree);
	while (temp) {
		curr = container_of(temp, struct nova_range_node, node);
		temp = rb_next(temp);
		rb_erase(&curr->node, tree);
		nova_free_range_node(curr);
	}
}

int nova_insert_blocktree(struct rb_root *tree,
	struct nova_range_node *new_node)
{
	int ret;

	ret = nova_insert_range_node(tree, new_node, NODE_BLOCK);
	if (ret)
		nova_dbg("ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

/* Used for both block free tree and inode inuse tree */
int nova_find_free_slot(struct rb_root *tree, unsigned long range_low,
	unsigned long range_high, struct nova_range_node **prev,
	struct nova_range_node **next)
{
	struct nova_range_node *ret_node = NULL;
	struct rb_node *tmp;
	int check_prev = 0, check_next = 0;
	int ret;

	ret = nova_find_range_node(tree, range_low, NODE_BLOCK, &ret_node);
	if (ret) {
		nova_dbg("%s ERROR: %lu - %lu already in free list\n",
			__func__, range_low, range_high);
		return -EINVAL;
	}

	if (!ret_node) {
		*prev = *next = NULL;
	} else if (ret_node->range_high < range_low) {
		*prev = ret_node;
		tmp = rb_next(&ret_node->node);
		if (tmp) {
			*next = container_of(tmp, struct nova_range_node, node);
			check_next = 1;
		} else {
			*next = NULL;
		}
	} else if (ret_node->range_low > range_high) {
		*next = ret_node;
		tmp = rb_prev(&ret_node->node);
		if (tmp) {
			*prev = container_of(tmp, struct nova_range_node, node);
			check_prev = 1;
		} else {
			*prev = NULL;
		}
	} else {
		nova_dbg("%s ERROR: %lu - %lu overlaps "
			 "with existing node %lu - %lu\n",
			 __func__, range_low, range_high, ret_node->range_low,
			ret_node->range_high);
		return -EINVAL;
	}

	return 0;
}

/*
 * blocknr: start block number
 * num: number of freed pages
 * btype: is large page?
 * log_page: is log page?
 */
static int nova_free_blocks(struct super_block *sb, unsigned long blocknr,
	int num, unsigned short btype, int log_page)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct rb_root *tree;
	unsigned long block_low;
	unsigned long block_high;
	unsigned long num_blocks = 0;
	struct nova_range_node *prev = NULL;
	struct nova_range_node *next = NULL;
	struct nova_range_node *curr_node;
	struct free_list *free_list;
	int cpuid;
	int new_node_used = 0;
	int ret;
	timing_t free_time;

	if (num <= 0) {
		nova_dbg("%s ERROR: free %d\n", __func__, num);
		return -EINVAL;
	}

	NOVA_START_TIMING(free_blocks_t, free_time);
	cpuid = blocknr / sbi->per_list_blocks;

	/* Pre-allocate blocknode */
	curr_node = nova_alloc_blocknode(sb);
	if (curr_node == NULL) {
		/* returning without freeing the block*/
		NOVA_END_TIMING(free_blocks_t, free_time);
		return -ENOMEM;
	}

	free_list = nova_get_free_list(sb, cpuid);
	spin_lock(&free_list->s_lock);

	tree = &(free_list->block_free_tree);

	num_blocks = nova_get_numblocks(btype) * num;
	block_low = blocknr;
	block_high = blocknr + num_blocks - 1;

	nova_dbgv("Free: %lu - %lu\n", block_low, block_high);

	if (blocknr < free_list->block_start ||
			blocknr + num > free_list->block_end + 1) {
		nova_err(sb, "free blocks %lu to %lu, free list %d, "
			 "start %lu, end %lu\n",
			 blocknr, blocknr + num - 1,
			 free_list->index,
			 free_list->block_start,
			 free_list->block_end);
		ret = -EIO;
		goto out;
	}

	ret = nova_find_free_slot(tree, block_low,
					block_high, &prev, &next);

	if (ret) {
		nova_dbg("%s: find free slot fail: %d\n", __func__, ret);
		goto out;
	}

	if (prev && next && (block_low == prev->range_high + 1) &&
			(block_high + 1 == next->range_low)) {
		/* fits the hole */
		rb_erase(&next->node, tree);
		free_list->num_blocknode--;
		prev->range_high = next->range_high;
		if (free_list->last_node == next)
			free_list->last_node = prev;
		nova_free_blocknode(next);
		goto block_found;
	}
	if (prev && (block_low == prev->range_high + 1)) {
		/* Aligns left */
		prev->range_high += num_blocks;
		goto block_found;
	}
	if (next && (block_high + 1 == next->range_low)) {
		/* Aligns right */
		next->range_low -= num_blocks;
		goto block_found;
	}

	/* Aligns somewhere in the middle */
	curr_node->range_low = block_low;
	curr_node->range_high = block_high;
	new_node_used = 1;
	ret = nova_insert_blocktree(tree, curr_node);
	if (ret) {
		new_node_used = 0;
		goto out;
	}
	if (!prev)
		free_list->first_node = curr_node;
	if (!next)
		free_list->last_node = curr_node;

	free_list->num_blocknode++;

block_found:
	free_list->num_free_blocks += num_blocks;

	if (log_page) {
		free_list->free_log_count++;
		free_list->freed_log_pages += num_blocks;
	} else {
		free_list->free_data_count++;
		free_list->freed_data_pages += num_blocks;
	}

out:
	spin_unlock(&free_list->s_lock);
	if (new_node_used == 0)
		nova_free_blocknode(curr_node);

	NOVA_END_TIMING(free_blocks_t, free_time);
	return ret;
}

int nova_free_data_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr, int num)
{
	int ret;
	timing_t free_time;

	nova_dbgv("Inode %lu: free %d data block from %lu to %lu\n",
			sih->ino, num, blocknr, blocknr + num - 1);
	if (blocknr == 0) {
		nova_dbg("%s: ERROR: %lu, %d\n", __func__, blocknr, num);
		return -EINVAL;
	}
	NOVA_START_TIMING(free_data_t, free_time);
	ret = nova_free_blocks(sb, blocknr, num, sih->i_blk_type, 0);
	if (ret) {
		nova_err(sb, "Inode %lu: free %d data block "
			 "from %lu to %lu failed!\n",
			 sih->ino, num, blocknr, blocknr + num - 1);
		dump_stack();
	}
	NOVA_END_TIMING(free_data_t, free_time);

	return ret;
}

int nova_free_log_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr, int num)
{
	int ret;
	timing_t free_time;

	nova_dbgv("Inode %lu: free %d log block from %lu to %lu\n",
			sih->ino, num, blocknr, blocknr + num - 1);
	if (blocknr == 0) {
		nova_dbg("%s: ERROR: %lu, %d\n", __func__, blocknr, num);
		return -EINVAL;
	}
	NOVA_START_TIMING(free_log_t, free_time);
	ret = nova_free_blocks(sb, blocknr, num, sih->i_blk_type, 1);
	if (ret) {
		nova_err(sb, "Inode %lu: free %d log block "
			 "from %lu to %lu failed!\n",
			 sih->ino, num, blocknr, blocknr + num - 1);
		dump_stack();
	}
	NOVA_END_TIMING(free_log_t, free_time);

	return ret;
}

static int not_enough_blocks(struct free_list *free_list,
	unsigned long num_blocks, enum alloc_type atype)
{
	struct nova_range_node *first = free_list->first_node;
	struct nova_range_node *last = free_list->last_node;

	if (free_list->num_free_blocks < num_blocks || !first || !last) {
		nova_dbgv("%s: num_free_blocks=%ld; num_blocks=%ld; "
			  "first=0x%p; last=0x%p",
			  __func__, free_list->num_free_blocks, num_blocks,
			  first, last);
		return 1;
	}

	return 0;
}

#define	PAGES_PER_2MB	512
#define	PAGES_PER_2MB_MASK	(512 - 1)

/* Both offset and blocks are aligned */
static inline bool alloc_request_is_superpage_aligned(unsigned long start_blk,
	unsigned long num_blocks, enum alloc_type atype)
{
	return (atype == DATA) &&
		!(start_blk & PAGES_PER_2MB_MASK) &&
		(num_blocks >= PAGES_PER_2MB);
}

/* Try to allocate aligned superpage */
static inline unsigned long get_avail_blocks(struct nova_range_node *curr)
{
	unsigned long curr_blocks = curr->range_high - curr->range_low + 1;
	unsigned int left_margin;

	if (curr_blocks < PAGES_PER_2MB)
		return 0;

	left_margin = PAGES_PER_2MB - (curr->range_low
						& PAGES_PER_2MB_MASK);
	if (curr_blocks <= left_margin ||
				curr_blocks - left_margin < PAGES_PER_2MB)
		return 0;

	return (curr_blocks - left_margin) & ~PAGES_PER_2MB_MASK;
}

static unsigned long nova_alloc_superpage(struct super_block *sb,
	struct free_list *free_list, enum nova_alloc_direction from_tail,
	unsigned long num_blocks, unsigned long *new_blocknr)
{
	struct rb_root *tree;
	struct nova_range_node *curr, *next = NULL, *prev = NULL, *node = NULL;
	struct rb_node *temp, *next_node, *prev_node;
	unsigned int left_margin;
	unsigned int right_margin;
	unsigned long curr_blocks;
	unsigned long range_high;
	unsigned long avail_blocks;
	unsigned long step = 0;
	int reuse_curr = 0;
	unsigned long allocated = 0;

	tree = &(free_list->block_free_tree);
	if (from_tail == ALLOC_FROM_HEAD)
		temp = &(free_list->first_node->node);
	else
		temp = &(free_list->last_node->node);

	while (temp) {
		step++;
		curr = container_of(temp, struct nova_range_node, node);
		avail_blocks = get_avail_blocks(curr);

		if (avail_blocks < PAGES_PER_2MB)
			goto next;

		if (num_blocks > avail_blocks)
			num_blocks = avail_blocks;

		curr_blocks = curr->range_high - curr->range_low + 1;

		left_margin = PAGES_PER_2MB - (curr->range_low
						& PAGES_PER_2MB_MASK);

		right_margin = curr_blocks - left_margin - num_blocks;
		range_high = curr->range_high;
		*new_blocknr = curr->range_low + left_margin;

		if (left_margin) {
			curr->range_high = (curr->range_low + PAGES_PER_2MB)
						& ~PAGES_PER_2MB_MASK;
			curr->range_high--;
			reuse_curr = 1;
		}

		if (right_margin) {
			if (reuse_curr == 0) {
				curr->range_low += left_margin + num_blocks;
				reuse_curr = 1;
			} else {
				node = nova_alloc_blocknode_atomic(sb);
				if (node == NULL) return -ENOMEM;

				node->range_low = curr->range_low + left_margin
								+ num_blocks;
				node->range_high = range_high;
				nova_insert_blocktree(tree, node);
				free_list->num_blocknode++;
				if (curr == free_list->last_node)
					free_list->last_node = node;
			}
		}

		if (reuse_curr == 0) {
			/* Allocate the whole blocknode */
			if (curr == free_list->first_node) {
				next_node = rb_next(temp);
				if (next_node)
					next = container_of(next_node,
						struct nova_range_node, node);
				free_list->first_node = next;
			}

			if (curr == free_list->last_node) {
				prev_node = rb_prev(temp);
				if (prev_node)
					prev = container_of(prev_node,
						struct nova_range_node, node);
				free_list->last_node = prev;
			}

			rb_erase(&curr->node, tree);
			free_list->num_blocknode--;
			nova_free_blocknode(curr);
		}

		allocated = num_blocks;
		nova_dbgv("%s: Allocate superpage %lu blocks from %lu\n",
				__func__, num_blocks, *new_blocknr);

		break;

next:
		if (from_tail == ALLOC_FROM_HEAD)
			temp = rb_next(temp);
		else
			temp = rb_prev(temp);
	}

	NOVA_STATS_ADD(alloc_steps, step);
	return allocated;
}

/* Return how many blocks allocated */
static long nova_alloc_blocks_in_free_list(struct super_block *sb,
	struct free_list *free_list, unsigned short btype,
	enum alloc_type atype, unsigned long start_blk,
	unsigned long num_blocks, unsigned long *new_blocknr,
	enum nova_alloc_direction from_tail)
{
	struct rb_root *tree;
	struct nova_range_node *curr, *next = NULL, *prev = NULL;
	struct rb_node *temp, *next_node, *prev_node;
	unsigned long curr_blocks;
	unsigned long allocated;
	bool found = 0;
	unsigned long step = 0;

	if (!free_list->first_node || free_list->num_free_blocks == 0) {
		nova_dbgv("%s: Can't alloc. free_list->first_node=0x%p "
			  "free_list->num_free_blocks = %lu",
			  __func__, free_list->first_node,
			  free_list->num_free_blocks);
		return -ENOSPC;
	}

	if (atype == LOG && not_enough_blocks(free_list, num_blocks, atype)) {
		nova_dbgv("%s: Can't alloc.  not_enough_blocks() == true",
			  __func__);
		return -ENOSPC;
	}

	/* Try superpage allocation */
	if (alloc_request_is_superpage_aligned(start_blk, num_blocks, atype)) {
		allocated = nova_alloc_superpage(sb, free_list,
					from_tail, num_blocks, new_blocknr);
		if (allocated) {
			num_blocks = allocated;
			found = 1;
			goto out;
		}
	}

	tree = &(free_list->block_free_tree);
	if (from_tail == ALLOC_FROM_HEAD)
		temp = &(free_list->first_node->node);
	else
		temp = &(free_list->last_node->node);

	while (temp) {
		step++;
		curr = container_of(temp, struct nova_range_node, node);

		curr_blocks = curr->range_high - curr->range_low + 1;

		if (num_blocks >= curr_blocks) {
			/* Superpage allocation must succeed */
			if (btype > 0 && num_blocks > curr_blocks)
				goto next;

			/* Otherwise, allocate the whole blocknode */
			if (curr == free_list->first_node) {
				next_node = rb_next(temp);
				if (next_node)
					next = container_of(next_node,
						struct nova_range_node, node);
				free_list->first_node = next;
			}

			if (curr == free_list->last_node) {
				prev_node = rb_prev(temp);
				if (prev_node)
					prev = container_of(prev_node,
						struct nova_range_node, node);
				free_list->last_node = prev;
			}

			rb_erase(&curr->node, tree);
			free_list->num_blocknode--;
			num_blocks = curr_blocks;
			*new_blocknr = curr->range_low;
			nova_free_blocknode(curr);
			found = 1;
			break;
		}

		/* Allocate partial blocknode */
		if (from_tail == ALLOC_FROM_HEAD) {
			*new_blocknr = curr->range_low;
			curr->range_low += num_blocks;
		} else {
			*new_blocknr = curr->range_high + 1 - num_blocks;
			curr->range_high -= num_blocks;
		}

		found = 1;
		break;
next:
		if (from_tail == ALLOC_FROM_HEAD)
			temp = rb_next(temp);
		else
			temp = rb_prev(temp);
	}

out:
	if (free_list->num_free_blocks < num_blocks) {
		nova_dbg("%s: free list %d has %lu free blocks, "
				"but allocated %lu blocks?\n",
				__func__, free_list->index,
				free_list->num_free_blocks, num_blocks);
		return -ENOSPC;
	}

	if (found == 1)
		free_list->num_free_blocks -= num_blocks;
	else {
		nova_dbgv("%s: Can't alloc.  found = %d", __func__, found);
		return -ENOSPC;
	}

	NOVA_STATS_ADD(alloc_steps, step);

	return num_blocks;
}

/* Find out the free list with most free blocks */
static int nova_get_candidate_free_list(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int cpuid = 0;
	int num_free_blocks = 0;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		if (free_list->num_free_blocks > num_free_blocks) {
			cpuid = i;
			num_free_blocks = free_list->num_free_blocks;
		}
	}

	return cpuid;
}

static int nova_new_blocks(struct super_block *sb, unsigned long *blocknr,
	unsigned long start_blk, unsigned int num, unsigned short btype,
	int zero, enum alloc_type atype, int cpuid,
	enum nova_alloc_direction from_tail)
{
	struct free_list *free_list;
	void *bp;
	unsigned long num_blocks = 0;
	unsigned long new_blocknr = 0;
	long ret_blocks = 0;
	int retried = 0;
	timing_t alloc_time;

	num_blocks = num * nova_get_numblocks(btype);
	if (num_blocks == 0) {
		nova_dbg_verbose("%s: num_blocks == 0", __func__);
		return -EINVAL;
	}

	NOVA_START_TIMING(new_blocks_t, alloc_time);
	if (cpuid == ANY_CPU)
		cpuid = nova_get_cpuid(sb);

retry:
	free_list = nova_get_free_list(sb, cpuid);
	spin_lock(&free_list->s_lock);

	if (not_enough_blocks(free_list, num_blocks, atype)) {
		nova_dbgv("%s: cpu %d, free_blocks %lu, required %lu, "
			  "blocknode %lu\n",
			  __func__, cpuid, free_list->num_free_blocks,
			  num_blocks, free_list->num_blocknode);

		if (retried >= 2)
			/* Allocate anyway */
			goto alloc;

		spin_unlock(&free_list->s_lock);
		cpuid = nova_get_candidate_free_list(sb);
		retried++;
		goto retry;
	}
alloc:
	ret_blocks = nova_alloc_blocks_in_free_list(sb, free_list, btype, atype,
				start_blk, num_blocks, &new_blocknr, from_tail);

	if (ret_blocks > 0) {
		if (atype == LOG) {
			free_list->alloc_log_count++;
			free_list->alloc_log_pages += ret_blocks;
		} else if (atype == DATA) {
			free_list->alloc_data_count++;
			free_list->alloc_data_pages += ret_blocks;
		}
	}

	spin_unlock(&free_list->s_lock);
	NOVA_END_TIMING(new_blocks_t, alloc_time);

	if (ret_blocks <= 0 || new_blocknr == 0) {
		nova_dbgv("%s: not able to allocate %d blocks. "
			  "ret_blocks=%ld; new_blocknr=%lu",
			  __func__, num, ret_blocks, new_blocknr);
		return -ENOSPC;
	}

	if (zero) {
		bp = nova_get_block(sb, nova_get_block_off(sb,
						new_blocknr, btype));
		memset_nt(bp, 0, PAGE_SIZE * ret_blocks);
	}
	*blocknr = new_blocknr;

	nova_dbg_verbose("Alloc %lu NVMM blocks 0x%lx\n", ret_blocks, *blocknr);
	return ret_blocks / nova_get_numblocks(btype);
}

// Allocate data blocks.  The offset for the allocated block comes back in
// blocknr.  Return the number of blocks allocated.
int nova_new_data_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long *blocknr,
	unsigned long start_blk, unsigned int num,
	enum nova_alloc_init zero, int cpu,
	enum nova_alloc_direction from_tail)
{
	int allocated;
	timing_t alloc_time;

	NOVA_START_TIMING(new_data_blocks_t, alloc_time);
	allocated = nova_new_blocks(sb, blocknr, start_blk, num,
			    sih->i_blk_type, zero, DATA, cpu, from_tail);
	NOVA_END_TIMING(new_data_blocks_t, alloc_time);
	if (allocated < 0) {
		nova_dbgv("FAILED: Inode %lu, start blk %lu, "
			  "alloc %d data blocks from %lu to %lu\n",
			  sih->ino, start_blk, allocated, *blocknr,
			  *blocknr + allocated - 1);
	} else {
		nova_dbgv("Inode %lu, start blk %lu, "
			  "alloc %d data blocks from %lu to %lu\n",
			  sih->ino, start_blk, allocated, *blocknr,
			  *blocknr + allocated - 1);
	}
	return allocated;
}


// Allocate log blocks. The offset for the allocated block comes back in
// blocknr.  Return the number of blocks allocated.
inline int nova_new_log_blocks(struct super_block *sb,
			struct nova_inode_info_header *sih,
			unsigned long *blocknr, unsigned int num,
			enum nova_alloc_init zero, int cpu,
			enum nova_alloc_direction from_tail)
{
	int allocated;
	timing_t alloc_time;

	NOVA_START_TIMING(new_log_blocks_t, alloc_time);
	allocated = nova_new_blocks(sb, blocknr, 0, num,
			    sih->i_blk_type, zero, LOG, cpu, from_tail);
	NOVA_END_TIMING(new_log_blocks_t, alloc_time);
	if (allocated < 0) {
		nova_dbgv("%s: ino %lu, failed to alloc %d log blocks",
			  __func__, sih->ino, num);
	} else {
		nova_dbgv("%s: ino %lu, alloc %d of %d log blocks %lu to %lu\n",
			  __func__, sih->ino, allocated, num, *blocknr,
			  *blocknr + allocated - 1);
	}
	return allocated;
}

/* We do not take locks so it's inaccurate */
unsigned long nova_count_free_blocks(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long num_free_blocks = 0;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		num_free_blocks += free_list->num_free_blocks;
	}

	return num_free_blocks;
}



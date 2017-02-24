/*
 * BRIEF DESCRIPTION
 *
 * Parity related methods.
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

/* Add delta (data diffs) to the parity stripe.
 *         delta
 *           |
 *           |bytes|
 *
 *     |.....|bytes|...|
 *     |     |
 * parity  offset
 * */
static int nova_delta_parity(void *parity, void *delta, 
	size_t offset, size_t bytes)
{
	unsigned int strp_size = NOVA_STRIPE_SIZE;
	unsigned char *par_ptr = (unsigned char *) parity;
	unsigned char *dlt_ptr = (unsigned char *) delta;
	unsigned int byte;

	if (offset + bytes > strp_size) {
		nova_dbg("%s: parity stripe length error\n", __func__);
		return -EIO;
	}

	for (byte = offset; byte < bytes; byte++) {
		/* FIXME: Make this work on wider types. */
		par_ptr[offset + byte] ^= dlt_ptr[byte];
	}

	return 0;
}

/* Compute parity for a whole block */
static int nova_block_parity(struct super_block *sb, void *parity, void *block)
{
	unsigned int strp;
	unsigned int strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned char *strp_ptr = (unsigned char *) block;

	if ((parity == NULL) || (block == NULL)) {
		nova_dbg("%s: pointer error\n", __func__);
		return -EINVAL;
	}

	memcpy(parity, strp_ptr, strp_size);
	strp_ptr += strp_size;
	for (strp = 1; strp < (sb->s_blocksize >> strp_shift); strp++) {
		nova_delta_parity(parity, strp_ptr, 0, strp_size);
		strp_ptr += strp_size;
	}

	return 0;
}

static int nova_update_block_parity(struct super_block *sb,
	unsigned long blocknr, void *parbuf, void *blockptr)
{
	unsigned char *par_addr;
	size_t strp_size = NOVA_STRIPE_SIZE;

	nova_block_parity(sb, parbuf, blockptr);

	par_addr = nova_get_parity_addr(sb, blocknr);

	nova_memunlock_range(sb, par_addr, strp_size);
	memcpy_to_pmem_nocache(par_addr, parbuf, strp_size);
	nova_memlock_range(sb, par_addr, strp_size);

	return 0;
}

int nova_update_pgoff_parity(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long pgoff)
{
	unsigned int strp_size = NOVA_STRIPE_SIZE;
	unsigned long blocknr;
	void *dax_mem = NULL;
	u64 blockoff;
	unsigned char *parbuf;

	/* parity buffer for rolling updates */
	parbuf = kmalloc(strp_size, GFP_KERNEL);
	if (!parbuf) {
		nova_err(sb, "%s: parity buffer allocation error\n",
				__func__);
		return -ENOMEM;
	}

	blockoff = nova_find_nvmm_block(sb, sih, entry, pgoff);
	dax_mem = nova_get_block(sb, blockoff);

	blocknr = nova_get_blocknr(sb, blockoff, sih->i_blk_type);
	nova_update_block_parity(sb, blocknr, parbuf, dax_mem);

	kfree(parbuf);

	return 0;
}

/* Update copy-on-write data parity.
 * TODO: Checksum the parity stripe? */
size_t nova_update_cow_parity(struct inode *inode, unsigned long blocknr,
	void *wrbuf, size_t offset, size_t bytes)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info        *si  = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	size_t blockoff;
	size_t blocksize = nova_inode_blk_size(sih);
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned char *blockptr, *strp_ptr, *bufptr, *parbuf;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned int strp_index, strp_offset;
	unsigned long block, blocks;

	bufptr   = wrbuf;
	blocks   = ((offset + bytes - 1) >> sb->s_blocksize_bits) + 1;
	blockoff = nova_get_block_off(sb, blocknr, sih->i_blk_type);
	blockptr = nova_get_block(sb, blockoff);

	/* strp_ptr: virtual address of a stripe
	 * strp_index: stripe index within a block
	 * strp_offset: byte offset within a stripe */
	strp_ptr = blockptr;
	strp_index = offset >> strp_shift;
	strp_offset = offset - (strp_index << strp_shift);

	/* parity buffer for rolling updates */
	parbuf = kmalloc(strp_size, GFP_KERNEL);
	if (parbuf == NULL) {
		nova_err(sb, "%s: parity buffer allocation error\n",
				__func__);
		return -ENOMEM;
	}

	for (block = 0; block < blocks; block++) {
		/* FIXME: Now always read from nvmm.
		 * Also need to read the write buffer. */
		nova_update_block_parity(sb, blocknr, parbuf, blockptr);

		blocknr  += 1;
		blockptr += blocksize;
	}

	kfree(parbuf);

	return 0;
}

/* Restore a stripe of data. */
int nova_restore_data(struct super_block *sb, unsigned long blocknr,
        unsigned int strp_id)
{
	unsigned int strp;
	unsigned int strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	size_t blockoff;
	unsigned long bad_strp_nr;
	unsigned char *blockptr, *bad_strp, *strp_ptr, *strp_buf, *par_addr;
	u32 csum_calc, csum_nvmm, *csum_addr;
	bool match;

	blockoff = nova_get_block_off(sb, blocknr, NOVA_BLOCK_TYPE_4K);
	blockptr = nova_get_block(sb, blockoff);
	strp_ptr = blockptr;
	bad_strp = blockptr + strp_id * strp_size;
	bad_strp_nr = (blockoff + strp_id * strp_size) >> strp_shift;

	strp_buf = kmalloc(strp_size, GFP_KERNEL);
	if (strp_buf == NULL) {
		nova_err(sb, "%s: stripe buffer allocation error\n",
				__func__);
		return -ENOMEM;
	}

	par_addr = nova_get_parity_addr(sb, blocknr);
	if (par_addr == NULL) {
		nova_err(sb, "%s: parity address error\n", __func__);
		return -EIO;
	}

	memcpy_from_pmem(strp_buf, par_addr, strp_size);

	for (strp = 0; strp < strp_id; strp++) {
		nova_delta_parity(strp_buf, strp_ptr, 0, strp_size);
		strp_ptr += strp_size;
	}

	strp_ptr += strp_size; // skip the bad stripe
	for (strp = strp_id + 1; strp < (sb->s_blocksize >> strp_shift); strp++) {
		nova_delta_parity(strp_buf, strp_ptr, 0, strp_size);
		strp_ptr += strp_size;
	}

	csum_calc = nova_calc_data_csum(NOVA_INIT_CSUM, strp_buf, strp_size);
	csum_addr = nova_get_data_csum_addr(sb, bad_strp_nr);
	csum_nvmm = le32_to_cpu(*csum_addr);
	match     = (csum_calc == csum_nvmm);

	if (match) {
		nova_memunlock_range(sb, bad_strp, strp_size);
	        memcpy_to_pmem_nocache(bad_strp, strp_buf, strp_size);
		nova_memlock_range(sb, bad_strp, strp_size);
	}

	kfree(strp_buf);

	if (match)
	        return 0;
	else
	        return -EIO;
}

int nova_data_parity_init_free_list(struct super_block *sb,
	struct free_list *free_list)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long blocksize, total_blocks, parity_blocks;
	unsigned int strp_size = NOVA_STRIPE_SIZE;

	/* Allocate blocks to store data block checksums.
	 * Always reserve in case user turns it off at init mount but later
	 * turns it on. */
	blocksize = sb->s_blocksize;
	total_blocks = sbi->initsize / blocksize;
	parity_blocks = total_blocks / (blocksize / strp_size + 1);
	if (total_blocks % (blocksize / strp_size + 1))
		parity_blocks++;

	free_list->parity_start = free_list->block_start;
	free_list->block_start += parity_blocks / sbi->cpus;
	if (parity_blocks % sbi->cpus)
		free_list->block_start++;

	free_list->num_parity_blocks =
		free_list->block_start - free_list->parity_start;

	return 0;
}


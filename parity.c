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

static int nova_calculate_block_parity(struct super_block *sb, u8 *parity,
	u8 *block)
{
	unsigned int strp, num_strps, i, j;
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	u64 xor;

	num_strps = sb->s_blocksize >> strp_shift;
	if ( static_cpu_has(X86_FEATURE_XMM2) ) { // sse2 128b
		for (i = 0; i < strp_size; i += 16) {
			asm volatile("movdqa %0, %%xmm0" : : "m" (block[i]));
			for (strp = 1; strp < num_strps; strp++) {
				j = (strp << strp_shift) + i;
				asm volatile(
					"movdqa     %0, %%xmm1\n"
					"pxor   %%xmm1, %%xmm0\n"
					: : "m" (block[j])
				);
			}
			asm volatile("movntdq %%xmm0, %0" : "=m" (parity[i]));
		}
	} else { // common 64b
		for (i = 0; i < strp_size; i += 8) {
			xor = *((u64 *) &block[i]);
			for (strp = 1; strp < num_strps; strp++) {
				j = (strp << strp_shift) + i;
				xor ^= *((u64 *) &block[j]);
			}
			*((u64 *) &parity[i]) = xor;
		}
	}

	return 0;
}

/* Compute parity for a whole data block and write the parity stripe to nvmm */
static int nova_update_block_parity(struct super_block *sb, void *block,
	unsigned long blocknr, int zero)
{
	size_t strp_size = NOVA_STRIPE_SIZE;
	void *parity, *nvmmptr;
	int ret = 0;

	parity = kmalloc(strp_size, GFP_KERNEL);
	if (parity == NULL) {
		nova_err(sb, "%s: parity buffer allocation error\n", __func__);
		ret = -ENOMEM;
		goto out;
	}

	if (block == NULL) {
		nova_dbg("%s: block pointer error\n", __func__);
		ret = -EINVAL;
		goto out;
	}

	if (unlikely(zero))
		memset(parity, 0, strp_size);
	else
		nova_calculate_block_parity(sb, parity, block);

	nvmmptr = nova_get_parity_addr(sb, blocknr);

	nova_memunlock_range(sb, nvmmptr, strp_size);
	memcpy_to_pmem_nocache(nvmmptr, parity, strp_size);
	nova_memlock_range(sb, nvmmptr, strp_size);

	// TODO: The parity stripe should be checksummed for higher reliability.
out:
	if (parity != NULL) kfree(parity);

	return 0;
}

int nova_update_pgoff_parity(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long pgoff, int zero)
{
	unsigned long blocknr;
	void *dax_mem = NULL;
	u64 blockoff;

	blockoff = nova_find_nvmm_block(sb, sih, entry, pgoff);
	/* Truncated? */
	if (blockoff == 0)
		return 0;

	dax_mem = nova_get_block(sb, blockoff);

	blocknr = nova_get_blocknr(sb, blockoff, sih->i_blk_type);
	nova_update_block_parity(sb, dax_mem, blocknr, zero);

	return 0;
}

/* Computes a parity stripe for one file write data block and writes the parity
 * stripe to nvmm.
 *
 * The block buffer to compute checksums should reside in dram (more trusted),
 * not in nvmm (less trusted).
 *
 * block:   block buffer with user data and possibly partial head-tail block
 *          - should be in kernel memory (dram) to avoid page faults
 * blocknr: destination nvmm block number where the block is written to
 *          - used to derive checksum value addresses
 */
int nova_update_file_write_parity(struct super_block *sb, void *block,
	unsigned long blocknr)
{
	timing_t file_write_parity_time;

	NOVA_START_TIMING(file_write_parity_t, file_write_parity_time);

	nova_update_block_parity(sb, block, blocknr, 0);

	NOVA_END_TIMING(file_write_parity_t, file_write_parity_time);

	return 0;
}

/* Restore a stripe of data. */
int nova_restore_data(struct super_block *sb, unsigned long blocknr,
        unsigned int bad_strp_id)
{
	unsigned int i, num_strps;
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	size_t blockoff, offset;
	unsigned long bad_strp_nr;
	u8 *blockptr, *bad_strp, *blockbuf, *stripe, *parity;
	u32 csum_calc, csum_nvmm, *csum_addr;
	bool match;
	timing_t restore_time;
	int ret = 0;

	NOVA_START_TIMING(restore_data_t, restore_time);
	blockoff = nova_get_block_off(sb, blocknr, NOVA_BLOCK_TYPE_4K);
	blockptr = nova_get_block(sb, blockoff);
	bad_strp = blockptr + (bad_strp_id << strp_shift);
	bad_strp_nr = (blockoff + (bad_strp_id << strp_shift)) >> strp_shift;

	stripe = kmalloc(strp_size, GFP_KERNEL);
	blockbuf = kmalloc(sb->s_blocksize, GFP_KERNEL);
	if (stripe == NULL || blockbuf == NULL) {
		nova_err(sb, "%s: buffer allocation error\n", __func__);
		ret = -ENOMEM;
		goto out;
	}

	parity = nova_get_parity_addr(sb, blocknr);
	if (parity == NULL) {
		nova_err(sb, "%s: parity address error\n", __func__);
		ret = -EIO;
		goto out;
	}

	num_strps = sb->s_blocksize >> strp_shift;
	for (i = 0; i < num_strps; i++) {
		offset = i << strp_shift;
		if (i == bad_strp_id)
			ret = memcpy_from_pmem(blockbuf + offset,
							parity, strp_size);
		else
			ret = memcpy_from_pmem(blockbuf + offset,
						blockptr + offset, strp_size);
		if (ret < 0) {
			nova_err(sb, "%s: unrecoverable media error\n",
							__func__);
			goto out;
		}
	}

	nova_calculate_block_parity(sb, stripe, blockbuf);

	csum_calc = nova_crc32c(NOVA_INIT_CSUM, stripe, strp_size);
	csum_addr = nova_get_data_csum_addr(sb, bad_strp_nr);
	csum_nvmm = le32_to_cpu(*csum_addr);
	match     = (csum_calc == csum_nvmm);

	if (match) {
		nova_memunlock_range(sb, bad_strp, strp_size);
	        memcpy_to_pmem_nocache(bad_strp, stripe, strp_size);
		nova_memlock_range(sb, bad_strp, strp_size);
	}

	if (!match) ret = -EIO;

out:
	if (stripe != NULL) kfree(stripe);
	if (blockbuf != NULL) kfree(blockbuf);

	NOVA_END_TIMING(restore_data_t, restore_time);
	return ret;
}

int nova_update_truncated_block_parity(struct super_block *sb,
	struct inode *inode, loff_t newsize)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned long pgoff, blocknr;
	u64 nvmm;
	char *nvmm_addr, *block;
	u8 btype = sih->i_blk_type;

	pgoff = newsize >> sb->s_blocksize_bits;

	nvmm = nova_find_nvmm_block(sb, sih, NULL, pgoff);
	if (nvmm == 0)
		return -EFAULT;

	nvmm_addr = (char *)nova_get_block(sb, nvmm);

	blocknr = nova_get_blocknr(sb, nvmm, btype);

	/* Copy to DRAM to catch MCE.
	block = kmalloc(blocksize, GFP_KERNEL);
	if (block == NULL) {
		nova_err(sb, "%s: buffer allocation error\n", __func__);
		return -ENOMEM;
	}
	*/

//	memcpy_from_pmem(block, nvmm_addr, blocksize);
	block = nvmm_addr;

	nova_update_block_parity(sb, block, blocknr, 0);

//	kfree(blkbuf);

	return 0;
}

int nova_data_parity_init_free_list(struct super_block *sb,
	struct free_list *free_list)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long blocksize, total_blocks, parity_blocks;
	size_t strp_size = NOVA_STRIPE_SIZE;

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


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

int nova_calculate_block_parity(struct super_block *sb,
	void *parity, void *block)
{
	unsigned int strp, num_strps, i, j;
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	u8 *par_ptr  = (u8 *) parity;
	u8 *strp_ptr = (u8 *) block;
	u64 xor;

	num_strps = sb->s_blocksize >> strp_shift;
	if ( static_cpu_has(X86_FEATURE_XMM2) ) { // sse2 128b
		for (i = 0; i < strp_size; i += 16) {
			asm volatile("movdqa %0, %%xmm0" : : "m" (strp_ptr[i]));
			for (strp = 1; strp < num_strps; strp++) {
				j = (strp << strp_shift) + i;
				asm volatile(
					"movdqa     %0, %%xmm1\n"
					"pxor   %%xmm1, %%xmm0\n"
					: : "m" (strp_ptr[j])
				);
			}
			asm volatile("movntdq %%xmm0, %0" : "=m" (par_ptr[i]));
		}
	} else { // common 64b
		for (i = 0; i < strp_size; i += 8) {
			xor = *((u64 *) &strp_ptr[i]);
			for (strp = 1; strp < num_strps; strp++) {
				j = (strp << strp_shift) + i;
				xor ^= *((u64 *) &strp_ptr[j]);
			}
			*((u64 *) &par_ptr[i]) = xor;
		}
	}

	return 0;
}

/* Compute parity for a whole data block and write the parity stripe to nvmm */
static int nova_update_block_parity(struct super_block *sb,
	unsigned long blocknr, void *parity, void *block, int zero)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	size_t strp_size = NOVA_STRIPE_SIZE;
	void *par_addr;

	if ((parity == NULL) || (block == NULL)) {
		nova_dbg("%s: pointer error\n", __func__);
		return -EINVAL;
	}

	if (unlikely(zero))
		parity = sbi->parity;
	else
		nova_calculate_block_parity(sb, parity, block);

	par_addr = nova_get_parity_addr(sb, blocknr);

	nova_memunlock_range(sb, par_addr, strp_size);
	memcpy_to_pmem_nocache(par_addr, parity, strp_size);
	nova_memlock_range(sb, par_addr, strp_size);

	return 0;
}

int nova_update_pgoff_parity(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long pgoff, int zero)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long blocknr;
	void *dax_mem = NULL;
	u64 blockoff;

	blockoff = nova_find_nvmm_block(sb, sih, entry, pgoff);
	/* Truncated? */
	if (blockoff == 0)
		return 0;

	dax_mem = nova_get_block(sb, blockoff);

	blocknr = nova_get_blocknr(sb, blockoff, sih->i_blk_type);
	nova_update_block_parity(sb, blocknr, sbi->parbuf, dax_mem, zero);

	return 0;
}

/* Update copy-on-write data parity stripes.
 *
 * The function computes a parity stripe for each copy-on-write data block and
 * writes the parity strpe to nvmm. The cow data (wrbuf) to compute parity
 * stripes should reside in dram (more trusted), not in nvmm (less trusted).
 * The data of wrbuf is already copied to nvmm.
 *
 * The parity stripe itself is not checksummed because it's only used during
 * data recovery, and the recovered data stripe is checksum-verified to tell if
 * the recovery was a success.
 *
 * blocknr:  destination nvmm block number where the wrbuf data is written to
 *           - used to derive parity stripe addresses
 * wrbuf:    cow data buffer, must be block-aligned and whole number of blocks
 *           - should have both partial head-tail block data and user data
 *           - should be in kernel memory (dram) to avoid page faults
 * wrblocks: number of blocks that wrbuf contains
 *
 * return:   blocks NOT parity-coded
 * */
size_t nova_update_cow_parity(struct inode *inode, unsigned long blocknr,
	void *wrbuf, int wrblocks)
{
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u8 *blockptr;
	unsigned long block;
	timing_t cow_parity_time;

	NOVA_START_TIMING(cow_parity_t, cow_parity_time);

	blockptr = (u8 *) wrbuf;

	for (block = 0; block < wrblocks; block++) {
		nova_update_block_parity(sb, blocknr, sbi->parbuf, blockptr, 0);

		blocknr  += 1;
		blockptr += sb->s_blocksize;
	}

	NOVA_END_TIMING(cow_parity_t, cow_parity_time);

	return 0;
}

/* Restore a stripe of data. */
int nova_restore_data(struct super_block *sb, unsigned long blocknr,
        unsigned int strp_id)
{
	unsigned int strp, num_strps, i, j;
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	size_t blockoff;
	unsigned long bad_strp_nr;
	u8 *blockptr, *bad_strp, *strp_ptr, *strp_buf, *par_addr;
	u32 csum_calc, csum_nvmm, *csum_addr;
	u64 xor;
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
		kfree(strp_buf);
		nova_err(sb, "%s: parity address error\n", __func__);
		return -EIO;
	}

	memcpy_from_pmem(strp_buf, par_addr, strp_size);

	num_strps = sb->s_blocksize >> strp_shift;
	if ( static_cpu_has(X86_FEATURE_XMM2) ) { // sse2 128b
		for (i = 0; i < strp_size; i += 16) {
			asm volatile("movdqa %0, %%xmm0" : : "m" (strp_buf[i]));
			for (strp = 0; strp < num_strps; strp++) {
				if (strp == strp_id) continue; // skip the bad
				j = (strp << strp_shift) + i;
				asm volatile(
					"movdqa     %0, %%xmm1\n"
					"pxor   %%xmm1, %%xmm0\n"
					: : "m" (strp_ptr[j])
				);
			}
			asm volatile("movntdq %%xmm0, %0" : "=m" (strp_buf[i]));
		}
	} else { // common 64b
		for (i = 0; i < strp_size; i += 8) {
			xor = *((u64 *) &strp_buf[i]);
			for (strp = 0; strp < num_strps; strp++) {
				if (strp == strp_id) continue; // skip the bad
				j = (strp << strp_shift) + i;
				xor ^= *((u64 *) &strp_ptr[j]);
			}
			*((u64 *) &strp_buf[i]) = xor;
		}
	}

	csum_calc = nova_crc32c(NOVA_INIT_CSUM, strp_buf, strp_size);
	csum_addr = nova_get_data_csum_addr(sb, bad_strp_nr);
	csum_nvmm = le32_to_cpu(*csum_addr);
	match     = (csum_calc == csum_nvmm);

	if (match) {
		nova_memunlock_range(sb, bad_strp, strp_size);
	        memcpy_to_pmem_nocache(bad_strp, strp_buf, strp_size);
		nova_memlock_range(sb, bad_strp, strp_size);
	}

	kfree(strp_buf);

	if (!match) return -EIO;

	return 0;
}

int nova_update_truncated_block_parity(struct super_block *sb,
	struct inode *inode, loff_t newsize)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned long pgoff, blocknr;
	u64 nvmm;
	char *nvmm_addr, *blkbuf;
	u8 btype = sih->i_blk_type;

	pgoff = newsize >> sb->s_blocksize_bits;

	nvmm = nova_find_nvmm_block(sb, sih, NULL, pgoff);
	if (nvmm == 0)
		return -EFAULT;

	nvmm_addr = (char *)nova_get_block(sb, nvmm);

	blocknr = nova_get_blocknr(sb, nvmm, btype);

	/* Copy to DRAM to catch MCE.
	blkbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (blkbuf == NULL) {
		nova_err(sb, "%s: buffer allocation error\n", __func__);
		return -ENOMEM;
	}
	*/

//	memcpy_from_pmem(blkbuf, nvmm_addr, PAGE_SIZE);
	blkbuf = nvmm_addr;

	nova_update_block_parity(sb, blocknr, sbi->parbuf, blkbuf, 0);

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

